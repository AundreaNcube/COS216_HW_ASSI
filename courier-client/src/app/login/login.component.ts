import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ToastrService } from 'ngx-toastr';
import { WebsocketService } from '../services/websocket.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [FormsModule],
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent {
  email: string = '';
  password: string = '';
  rememberMe: boolean = false;

  private loginAttempts: number = 0;
  private readonly maxAttempts: number = 5;
  private lockoutUntil: number = 0;

  constructor(
    private toastr: ToastrService,
    private websocketService: WebsocketService
  ) {
    this.websocketService.getMessages().subscribe({
      next: (message) => this.handleWebSocketMessage(message),
      error: (error) => this.toastr.error('WebSocket error: ' + error)
    });
  }

  onSubmit() {
    const now = Date.now();
    if (this.lockoutUntil > now) {
      const secondsLeft = Math.ceil((this.lockoutUntil - now) / 1000);
      this.toastr.error(`Please wait ${secondsLeft} seconds`);
      return;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

    if (!emailRegex.test(this.email)) {
      this.toastr.error('Invalid email format');
      this.handleFailedAttempt();
      return;
    }

    if (!passwordRegex.test(this.password)) {
      this.toastr.error('Must contain uppercase(A-Z), lowercase(a-z), number(0-9), and special character (8+ chars)');
      this.handleFailedAttempt();
      return;
    }

    this.websocketService.sendMessage({
      type: 'login',
      email: this.email,
      password: this.password
    });
  }

  private handleWebSocketMessage(message: any) {
    if (message.type === 'login_success') {
      this.loginAttempts = 0;
      localStorage.setItem('apikey', message.apikey);
      localStorage.setItem('name', message.name);
      localStorage.setItem('surname', message.surname);
      localStorage.setItem('userType', message.userType);
      localStorage.setItem('preferences', JSON.stringify(message.preferences));
      this.toastr.success(`Welcome ${message.name} ${message.surname}!`);
      if (this.rememberMe) {
        localStorage.setItem('rememberMe', 'true');
        localStorage.setItem('email', this.email);
      }
    } else if (message.type === 'error') {
      this.handleFailedAttempt();
      this.toastr.error(message.message);
      if (message.lockout_until) {
        this.lockoutUntil = message.lockout_until;
      }
    }
  }

  private handleFailedAttempt() {
    this.loginAttempts++;
    if (this.loginAttempts >= this.maxAttempts) {
      this.lockoutUntil = Date.now() + 2 * 60 * 1000; // 2-minute lockout
      this.toastr.error('Too many login attempts. Please wait.');
    }
  }
}