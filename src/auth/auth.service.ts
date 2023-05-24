import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

import { UserService } from './../user/user.service';

@Injectable()
export class AuthService {
  constructor(private readonly userService: UserService) {}
  async validateUser(email: string, password: string) {
    const user = await this.userService.findByEmail(email);

    if (user) {
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (isPasswordValid) return { ...user, password: undefined };
    }

    throw new Error('email address or password provided is incorrect');
  }

  login() {
    return 'login!';
  }
}
