# Secure Authentication API

A robust authentication API built with Node.js, TypeScript, and Prisma, featuring advanced security measures, comprehensive logging, and scalable architecture.

## 🚀 Key Features

### Authentication & Authorization

- **JWT-based Authentication** with access and refresh token mechanism
- **Secure Password Hashing** using bcrypt with configurable salt rounds
- **Multi-device Session Management** with device-specific token validation
- **Comprehensive Logout System** supporting single device and all-device logout
- **Token Rotation Security** - automatic refresh token rotation on each use

### Security Features

- **Advanced Rate Limiting** with different limits for various endpoints
- **Helmet.js Integration** for security headers
- **CSRF Protection** with secure cookie handling
- **SQL Injection Prevention** through Prisma ORM
- **Input Validation** using Zod schemas with detailed error messages
- **Password Complexity Requirements** enforced at validation layer

### Password Recovery

- **Secure Password Reset Flow** with time-limited tokens
- **Email Template System** using Pug templates
- **Token Hashing** for secure storage of reset tokens
- **Rate-limited Reset Requests** to prevent abuse

### Monitoring & Logging

- **Comprehensive Audit Logging** for all authentication events
- **Event-driven Architecture** with detailed metadata tracking
- **Performance Monitoring** with database operation logging
- **Client Information Tracking** (IP, User Agent) for security analysis

## 🛠 Technical Stack

- **Runtime**: Node.js with TypeScript
- **Framework**: Express.js with middleware architecture
- **Database**: PostgreSQL with Prisma ORM
- **Caching**: Redis for session management
- **Email**: Nodemailer with Gmail integration
- **Security**: Helmet, bcrypt, JWT
- **Validation**: Zod schemas
- **Testing**: Jest with comprehensive unit tests
- **Code Quality**: ESLint, Prettier

## 📡 API Endpoints

### Authentication

```
POST /api/auth/register          # User registration
POST /api/auth/login             # User login
POST /api/auth/refresh           # Token refresh
POST /api/auth/logout            # Single device logout
POST /api/auth/logout-all        # All devices logout
```

### Password Management

```
POST /api/auth/request-password-reset    # Request password reset
POST /api/auth/reset-password           # Reset password with token
```

## 🔧 Core Services

### [`loginService`](src/services/auth/login.service.ts)

- User credential validation
- Secure token generation and storage
- Comprehensive event logging
- Error handling with appropriate status codes

### [`tokenService`](src/services/auth/token.service.ts)

- JWT token verification and refresh
- Token rotation with security linking
- Client information validation
- Database transaction management

### [`registerService`](src/services/auth/register.service.ts)

- User registration with duplicate prevention
- Password hashing with bcrypt
- Welcome email automation
- Input sanitization and validation

### [`logoutService`](src/services/auth/logout.service.ts)

- Single and bulk token revocation
- Secure token invalidation
- Session cleanup across devices
- Audit trail maintenance

### [`passwordResetService`](src/services/auth/password-reset.service.ts)

- Secure token generation and validation
- Time-limited reset functionality
- Email delivery with custom templates
- Token usage tracking

## 🔐 Security Implementation

### Token Management

- **SHA-256 Token Hashing** for secure database storage
- **Unique JTI (JWT ID)** for each token to prevent replay attacks
- **Client Fingerprinting** using IP and User-Agent validation
- **Automatic Token Expiration** with configurable lifespans

### Middleware Stack

- **[`authMiddleware`](src/middlewares/auth.middleware.ts)**: JWT validation and user context
- **[`validateMiddleware`](src/middlewares/validate.middleware.ts)**: Request schema validation
- **[`errorMiddleware`](src/middlewares/error.middleware.ts)**: Centralized error handling

### Configuration Management

- **Environment-based Configuration** with validation in [`env.ts`](src/config/env.ts)
- **Secure Defaults** for production deployment
- **Database Connection Management** with [`prisma-client.ts`](src/config/prisma-client.ts)

## 📊 Database Schema

The application uses Prisma with the following key models:

- **User**: Core user information with secure password storage
- **RefreshToken**: Device-specific token management with metadata
- **PasswordReset**: Time-limited password reset tokens
- **AuditLog**: Comprehensive event tracking

## 🧪 Testing Strategy

- **Unit Tests**: 95%+ coverage with comprehensive test suites
- **Security Testing**: Token manipulation and injection attack prevention
- **Performance Testing**: Concurrent request handling and database optimization
- **Edge Case Coverage**: Malformed input and error condition handling

## 📧 Email System

Custom email templates using Pug:

- **[Welcome Email](src/utils/templates/welcome-email.pug)**: User registration confirmation
- **[Password Reset](src/utils/templates/reset-password-email.pug)**: Secure reset instructions
- **Responsive Design** with consistent branding

## 🚦 Rate Limiting

Configurable rate limiting for different endpoint types:

- **Authentication Endpoints**: Stricter limits to prevent brute force
- **Password Reset**: Additional protection against abuse
- **Token Refresh**: Balanced limits for user experience

## 📈 Performance Features

- **Connection Pooling** with Prisma
- **Async/Await** patterns throughout
- **Error Boundary Implementation** for graceful degradation
- **Memory-efficient** token handling and validation

## 🔧 Installation & Setup

```bash
# Install dependencies
npm install

# Set up environment variables
cp .env.example .env

# Run database migrations
npx prisma migrate dev

# Start development server
npm run dev

# Run tests
npm test
```

## 🌟 Production Ready

- **Graceful Shutdown** handling
- **Error Recovery** mechanisms
- **Comprehensive Logging** for debugging and monitoring
