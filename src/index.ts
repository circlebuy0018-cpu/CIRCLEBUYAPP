import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import admin from 'firebase-admin';
import { z } from 'zod';

// Initialize Firebase Admin
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.applicationDefault(),
  });
}

const app = express();

// CORS configuration
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://your-domain.com'] 
    : ['http://localhost:3000', 'http://localhost:8081', 'http://10.0.2.2:8000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Additional headers for mobile requests
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With');
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

app.use(express.json({ limit: '10mb' }));
app.use(morgan('dev'));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Simple health
app.get('/health', (_req, res) => res.json({ ok: true }));

// Auto-assign role on first login with domain validation
app.post('/auth/assign-role', verifyAuth, async (req, res) => {
  try {
    const caller = (req as any).user as admin.auth.DecodedIdToken;
    const superAdminEmail = process.env.SUPERADMIN_EMAIL || 'circlebuy0018@gmail.com';
    
    // Always check domain restrictions, ignore cached roles for security
    console.log('Processing auth for:', caller.email, 'Current role:', caller.role);
    
    // Check if super admin
    if (caller.email === superAdminEmail) {
      await admin.auth().setCustomUserClaims(caller.uid, { role: 'super_admin' });
      return res.json({ role: 'super_admin' });
    }
    
    // Check if user is an assigned admin (can be from any domain)
    try {
      const adminMarketplaceSnap = await admin.firestore()
        .collection('marketplaces')
        .where('adminEmail', '==', caller.email)
        .where('status', '==', 'active')
        .limit(1)
        .get();
      
      if (!adminMarketplaceSnap.empty) {
        const marketplace = adminMarketplaceSnap.docs[0];
        const marketplaceId = marketplace.id;
        console.log('Assigning admin role to:', caller.email, 'for marketplace:', marketplaceId);
        await admin.auth().setCustomUserClaims(caller.uid, { 
          role: 'admin', 
          marketplaceId 
        });
        return res.json({ role: 'admin', marketplaceId });
      }
    } catch (error) {
      console.error('Error checking admin status:', error);
    }
    
    // Check if email domain is authorized for regular users
    const emailDomain = caller.email?.split('@')[1];
    console.log('Checking email domain:', emailDomain, 'for user:', caller.email);
    
    if (!emailDomain) {
      console.log('Invalid email format');
      return res.status(403).json({ error: 'Invalid email format' });
    }
    
    // Block all public domains for regular users (not admins)
    const publicDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com'];
    const isPublicDomain = publicDomains.includes(emailDomain.toLowerCase());
    
    console.log('Is public domain?', isPublicDomain, 'Domain:', emailDomain);
    
    if (isPublicDomain) {
      console.log('Blocking public domain for regular user:', emailDomain);
      return res.status(403).json({ 
        error: 'Unauthorized domain. Please login with your university email that is collaborated with us.' 
      });
    }
    
    // Check if domain exists in active marketplaces
    try {
      const marketplaceSnap = await admin.firestore()
        .collection('marketplaces')
        .where('domain', '==', emailDomain.toLowerCase())
        .where('status', '==', 'active')
        .limit(1)
        .get();
      
      if (marketplaceSnap.empty) {
        console.log('Domain not found in active marketplaces:', emailDomain);
        return res.status(403).json({ 
          error: 'Unauthorized domain. Please login with your university email that is collaborated with us.' 
        });
      }
      
      const marketplace = marketplaceSnap.docs[0];
      const marketplaceData = marketplace.data();
      const marketplaceId = marketplace.id;
      
      // Regular user from authorized domain (admin check already done above)
      console.log('Assigning user role for domain:', emailDomain);
      await admin.auth().setCustomUserClaims(caller.uid, { 
        role: 'user', 
        marketplaceId 
      });
      return res.json({ role: 'user', marketplaceId });
      
    } catch (firestoreError) {
      console.error('Firestore error:', firestoreError);
      // If Firestore fails, block access for security
      return res.status(403).json({ 
        error: 'Unable to verify domain authorization.' 
      });
    }
  } catch (error) {
    console.error('Error assigning role:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Middleware: verify Firebase ID token from client if needed
async function verifyAuth(req: any, res: any, next: any) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const decoded = await admin.auth().verifyIdToken(token, true);
    (req as any).user = decoded;
    return next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Create marketplace (Super Admin only)
const CreateMarketplaceSchema = z.object({ 
  name: z.string().min(3), 
  domain: z.string().min(3),
  adminEmail: z.string().email()
});
app.post('/marketplaces/create', verifyAuth, async (req, res) => {
  try {
    const caller = (req as any).user as admin.auth.DecodedIdToken;
    if (caller.role !== 'super_admin') {
      return res.status(403).json({ error: 'Only super admin can create marketplaces' });
    }
    
    const parsed = CreateMarketplaceSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

    const { name, domain, adminEmail } = parsed.data;
    
    // Create marketplace
    const marketplaceRef = await admin.firestore().collection('marketplaces').add({
      name,
      domain,
      adminEmail,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      stats: { totalUsers: 0, totalProducts: 0, pendingProducts: 0 }
    });
    
    // Assign admin role
    try {
      const userRecord = await admin.auth().getUserByEmail(adminEmail);
      await admin.auth().setCustomUserClaims(userRecord.uid, { 
        role: 'admin', 
        marketplaceId: marketplaceRef.id 
      });
      
      // Create admin record
      await admin.firestore().collection('admins').doc(userRecord.uid).set({
        email: adminEmail,
        marketplaceId: marketplaceRef.id,
        assignedAt: admin.firestore.FieldValue.serverTimestamp()
      });
    } catch (error) {
      console.log('Admin user not found, will be assigned when they first login');
    }
    
    return res.json({ marketplaceId: marketplaceRef.id });
  } catch (error) {
    console.error('Error creating marketplace:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all marketplaces (Super Admin only)
app.get('/marketplaces', verifyAuth, async (req, res) => {
  try {
    const caller = (req as any).user as admin.auth.DecodedIdToken;
    if (caller.role !== 'super_admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const snapshot = await admin.firestore().collection('marketplaces').get();
    const marketplaces = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    
    return res.json({ marketplaces });
  } catch (error) {
    console.error('Error fetching marketplaces:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete marketplace with all data (Super Admin only)
app.delete('/marketplaces/:id', verifyAuth, async (req, res) => {
  try {
    const caller = (req as any).user as admin.auth.DecodedIdToken;
    if (caller.role !== 'super_admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const marketplaceId = req.params.id;
    
    // Delete only data from this marketplace
    const deleteMarketplaceData = async (collectionName: string, field: string) => {
      const query = admin.firestore().collection(collectionName)
        .where(field, '==', marketplaceId)
        .limit(500);
      
      let snapshot = await query.get();
      while (!snapshot.empty) {
        const batch = admin.firestore().batch();
        snapshot.docs.forEach(doc => batch.delete(doc.ref));
        await batch.commit();
        snapshot = await query.get();
      }
    };
    
    // Delete products from this marketplace only
    await deleteMarketplaceData('products', 'marketplaceId');
    
    // Delete users from this marketplace only
    await deleteMarketplaceData('users', 'marketplaceId');
    
    // Delete chats from this marketplace only
    await deleteMarketplaceData('chats', 'marketplaceId');
    
    // Delete marketplace
    await admin.firestore().collection('marketplaces').doc(marketplaceId).delete();
    
    return res.json({ success: true, message: 'Marketplace and all data deleted' });
  } catch (error) {
    console.error('Error deleting marketplace:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Clean up orphaned data (Super Admin only)
app.post('/cleanup-orphaned-data', verifyAuth, async (req, res) => {
  try {
    const caller = (req as any).user as admin.auth.DecodedIdToken;
    if (caller.role !== 'super_admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    // Get all active marketplace IDs
    const marketplacesSnapshot = await admin.firestore().collection('marketplaces').get();
    const activeMarketplaceIds = marketplacesSnapshot.docs.map(doc => doc.id);
    
    let deletedCount = 0;
    
    // Clean orphaned products
    const productsSnapshot = await admin.firestore().collection('products').get();
    for (const doc of productsSnapshot.docs) {
      const data = doc.data();
      if (!activeMarketplaceIds.includes(data.marketplaceId)) {
        await doc.ref.delete();
        deletedCount++;
      }
    }
    
    // Clean orphaned users
    const usersSnapshot = await admin.firestore().collection('users').get();
    for (const doc of usersSnapshot.docs) {
      const data = doc.data();
      if (!activeMarketplaceIds.includes(data.marketplaceId)) {
        await doc.ref.delete();
        deletedCount++;
      }
    }
    
    return res.json({ success: true, deletedCount, message: `Cleaned up ${deletedCount} orphaned records` });
  } catch (error) {
    console.error('Error cleaning orphaned data:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Block/Unblock user (Admin only)
const BlockUserSchema = z.object({ userId: z.string(), blocked: z.boolean() });
app.post('/users/block', verifyAuth, async (req, res) => {
  try {
    const caller = (req as any).user as admin.auth.DecodedIdToken;
    if (caller.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins can block users' });
    }
    
    const parsed = BlockUserSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

    const { userId, blocked } = parsed.data;
    
    await admin.firestore().collection('users').doc(userId).update({ blocked });
    
    // If blocking, revoke all refresh tokens to force logout
    if (blocked) {
      await admin.auth().revokeRefreshTokens(userId);
    }
    
    return res.json({ success: true });
  } catch (error) {
    console.error('Error blocking user:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});



// Get marketplace users (Admin only)
app.get('/users', verifyAuth, async (req, res) => {
  try {
    const caller = (req as any).user as admin.auth.DecodedIdToken;
    if (caller.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins can view users' });
    }
    
    const snapshot = await admin.firestore()
      .collection('users')
      .where('marketplaceId', '==', caller.marketplaceId)
      .get();
    
    const users = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    return res.json({ users });
  } catch (error) {
    console.error('Error fetching users:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

const PORT = process.env.PORT || 8000;
app.listen(PORT, '0.0.0.0', () => console.log(`CircleBuy server listening on 0.0.0.0:${PORT}`));