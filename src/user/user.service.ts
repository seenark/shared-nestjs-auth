import { Injectable } from "@nestjs/common";
import { Prisma } from "@prisma/client";
import { PrismaService } from "src/prisma/prisma.service";

@Injectable()
export class UserService {
  constructor(private prismaService: PrismaService) {}

  async createUser(data: Prisma.UserCreateInput) {
    const user = await this.prismaService.user.create({
      data: data,
    });
    return user;
  }

  async getAllUser() {
    return await this.prismaService.user.findMany();
  }

  async getUserById(id: string) {
    return await this.prismaService.user.findUnique({
      where: {
        id: id,
      },
    });
  }

  async updateUser(id: string, data: Prisma.UserUpdateInput) {
    const user = await this.prismaService.user.update({
      where: {
        id,
      },
      data: data,
    });
    return user;
  }

  async deleteUser(id: string) {
    const user = await this.prismaService.user.delete({
      where: {
        id,
      },
    });
    return user;
  }
}
