import { Injectable } from "@nestjs/common";
import { Prisma } from "@prisma/client";
import { PrismaService } from "src/prisma/prisma.service";
import { PasswordService } from "src/auth/password/password.service";

@Injectable()
export class UserService {
  constructor(
    private prismaService: PrismaService,
    private passwordService: PasswordService,
  ) {}

  async createUser(data: Prisma.UserCreateInput) {
    const hashedPassword = await this.passwordService.hashPassword(
      data.password,
    );
    const user = await this.prismaService.user.create({
      data: {
        ...data,
        password: hashedPassword,
      },
    });
    return user;
  }

  async getAllUser() {
    return await this.prismaService.user.findMany();
  }

  async getUserById(id: number) {
    return await this.prismaService.user.findUnique({
      where: {
        id: id,
      },
    });
  }

  async getUserByEmail(email: string) {
    return this.prismaService.user.findUnique({
      where: {
        email: email,
      },
    });
  }

  async updateUser(id: number, data: Prisma.UserUpdateInput) {
    const user = await this.prismaService.user.update({
      where: {
        id,
      },
      data: data,
    });
    return user;
  }

  async deleteUser(id: number) {
    const user = await this.prismaService.user.delete({
      where: {
        id,
      },
    });
    return user;
  }
}
