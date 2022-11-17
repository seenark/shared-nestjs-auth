import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from "@nestjs/common";
import { Request } from "express";
import { AuthService } from "src/auth/auth.service";

@Injectable()
export class RefreshTokenGuard implements CanActivate {
  constructor(private authService: AuthService) {}

  async canActivate(context: ExecutionContext) {
    const req: Request = context.switchToHttp().getRequest();
    const refreshJwt = req.cookies.refresh;
    if (!refreshJwt) {
      throw new UnauthorizedException("not found refresh token");
    }
    const userAgent = req.headers["user-agent"];

    const [valid, refreshPayload] = await this.authService.validateRefreshToken(
      refreshJwt,
      userAgent,
    );

    if (!valid) {
      throw new UnauthorizedException("invalid refresh token");
    }
    (req as any).payload = refreshPayload;

    return true;
  }
}
