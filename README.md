# CircleBuy Server

Backend API for CircleBuy marketplace application.

## Deployment

This server is configured for Railway deployment.

### Environment Variables Required:
- `GOOGLE_APPLICATION_CREDENTIALS` - Firebase service account JSON
- `SUPERADMIN_EMAIL` - Super admin email address
- `PORT` - Server port (default: 8000)

### Build Commands:
- Build: `npm run build`
- Start: `npm start`
- Development: `npm run dev`