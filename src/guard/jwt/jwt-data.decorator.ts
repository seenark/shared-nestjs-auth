import { createParamDecorator, ExecutionContext } from "@nestjs/common";

export interface IJwtPayload {
  email: string;
  name: string;
  iat: number;
  exp: number;
}

export const JwtPayload = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return <IJwtPayload>request.user;
  },
);
