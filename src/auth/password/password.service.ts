import { Injectable } from "@nestjs/common";
import { hashSync, verifySync } from "@node-rs/argon2";

@Injectable()
export class PasswordService {
  async hashPassword(password: string) {
    const passwordHashed = hashSync(password);
    return passwordHashed;
  }

  async verify(password: string, hash: string) {
    return verifySync(hash, password);
  }
}
