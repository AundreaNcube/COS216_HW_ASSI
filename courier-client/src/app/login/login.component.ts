import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { LoginService } from '../services/login.service';
import { WebsocketService } from '../services/websocket.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent {
  email: string = '';
  password: string = '';
  errorMessage: string = '';

  constructor(
    private loginService: LoginService,
    private websocketService: WebsocketService,
    private router: Router
  ) {}

  login(): void {
    console.log('Login attempt:', {
      email: this.email,
      password: this.password ? '[REDACTED]' : 'MISSING'
    });

    // Step 1: Authenticate via REST API
    this.loginService.login(this.email, this.password).subscribe({
      next: (response) => {
        console.log('REST API login response:', JSON.stringify(response, null, 2));
        localStorage.clear();
        localStorage.setItem('apikey', response.apikey);
        localStorage.setItem('email', this.email);
        localStorage.setItem('userType', response.userType);

        // Step 2: Authenticate via WebSocket
        this.websocketService.sendMessage({ type: 'login', email: this.email, password: this.password });

        // Subscribe to WebSocket messages for login response
        const subscription = this.websocketService.getMessages().subscribe({
          next: (message) => {
            console.log('WebSocket message:', JSON.stringify(message, null, 2));
            if (message.type === 'login_success') {
              console.log('WebSocket login successful:', {
                sessionId: message.sessionId,
                userType: message.userType
              });
              localStorage.setItem('userType', message.userType);
              this.navigateToDashboard(subscription);
            } else if (message.type === 'error' || message.type === 'auth_error' || message.type === 'connection_error') {
              console.error('WebSocket login error:', message.message);
              this.errorMessage = message.message === 'Connected to HTTP server instead of WebSocket. Check server configuration.'
                ? 'WebSocket server misconfigured. Contact support or try again later.'
                : message.message || 'WebSocket authentication failed';
              localStorage.clear();
              subscription.unsubscribe();
            }
          },
          error: (err) => {
            console.error('WebSocket subscription error:', err);
            this.errorMessage = 'Failed to connect to WebSocket server. Please try again later.';
            localStorage.clear();
            subscription.unsubscribe();
          }
        });
      },
      error: (error) => {
        console.error('REST API login error:', {
          message: error.message,
          status: error.status,
          details: JSON.stringify(error, null, 2)
        });
        this.errorMessage = error.message.includes('CORS error')
          ? 'CORS policy error. The server is not configured to allow requests from this application. Contact support.'
          : error.status === 0
            ? 'Cannot connect to the API server. Check your network or contact support.'
            : error.message || 'Login failed';
      }
    });
  }

  private navigateToDashboard(subscription: any): void {
    this.router.navigate(['/dashboard']).then(success => {
      console.log('Navigation to dashboard successful:', success);
      subscription.unsubscribe();
    }).catch(err => {
      console.error('Navigation to dashboard failed:', err);
      this.errorMessage = 'Navigation failed. Please try again.';
      subscription.unsubscribe();
    });
  }

  logout(): void {
    localStorage.clear();
    this.router.navigate(['/login']);
  }
}