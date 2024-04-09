import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { LoginUserDto, RegisterUserDto } from './dto';
import { JwtPaylod } from 'src/interfaces';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDB Connected');
  }

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  async signJwtToken(payload: JwtPaylod) {
    return this.jwtService.sign(payload);
  }
  async registerUser(registerUserDto: RegisterUserDto) {
    const { email, name, password } = registerUserDto;

    try {
      const user = await this.user.findFirst({
        where: { email },
      });

      if (user)
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'User already exists',
        });

      const newUser = await this.user.create({
        data: {
          name,
          email,
          password: bcrypt.hashSync(password, 10),
        },
      });

      delete newUser.password;
      const token = await this.signJwtToken(user);

      return { user: newUser, token };
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.BAD_REQUEST,
        message: error.message,
      });
    }
  }
  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;

    try {
      const user = await this.user.findFirst({
        where: { email },
      });

      if (!user)
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'Email Or Password do not match',
        });

      const isPasswordValid = bcrypt.compareSync(password, user.password);

      if (!isPasswordValid)
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'Email Or Password do not match',
        });

      delete user.password;
      const token = await this.signJwtToken(user);

      return { user, token };
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.BAD_REQUEST,
        message: error.message,
      });
    }
  }

  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwt_secret,
      });
      const newToken = await this.signJwtToken(user);
      return { user, token: newToken };
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.UNAUTHORIZED,
        message: `Invalid token: ${error.message}`,
      });
    }
  }
}
