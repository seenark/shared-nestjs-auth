import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import { IJwtAndRefreshPayload } from "src/auth/auth.service";

export const RefreshPayload = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return <IJwtAndRefreshPayload>request.payload;
  },
);
