import { z } from "zod";
import { createZodDto } from "@anatine/zod-nestjs";
import { ApiProperty } from "@nestjs/swagger";

const UserSchema = z.object({
  name: z.string(),
  email: z.string(),
  password: z.string(),
});
export class UserDto extends createZodDto(UserSchema) {}

export const UserResponseSchema = z.object({
  name: z.string(),
  email: z.string(),
});

export class UserResponseDto extends createZodDto(UserResponseSchema) {}

export class ProfileImage {
  @ApiProperty({ type: "string", format: "binary" })
  image: string;

  @ApiProperty({ type: "string" })
  name: string;
}
