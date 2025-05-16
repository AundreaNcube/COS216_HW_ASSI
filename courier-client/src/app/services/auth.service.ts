import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of, throwError } from 'rxjs';
import { catchError, map, tap } from 'rxjs/operators';
import { Router } from '@angular/router';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'http://your-api-url/api'; // Replace with your actual API URL
  private isAuthenticated = false;

  constructor(
    private http: HttpClient,
    private router: Router
  ) {
    // Check if the user is already logged in
    this.isAuthenticated = localStorage.getItem('isLoggedIn') === 'true';
  }

  login(username: string, password: string): Observable<any> {
    // For development, you might want to mock the login
    // Remove this block when connecting to a real API
    if (username === 'admin' && password === 'admin') {
      this.isAuthenticated = true;
      localStorage.setItem('isLoggedIn', 'true');
      return of({ success: true, user: { username: 'admin', role: 'admin' } });
    }

    // Real API implementation
    return this.http.post<any>(`${this.apiUrl}/auth/login`, { username, password })
      .pipe(
        tap(response => {
          if (response && response.token) {
            this.isAuthenticated = true;
            localStorage.setItem('isLoggedIn', 'true');
            localStorage.setItem('token', response.token);
            // Store other user info as needed
          }
        }),
        catchError(error => {
          console.error('Login error:', error);
          return throwError(() => new Error('Login failed. Please check your credentials.'));
        })
      );
  }

  logout(): void {
    // Clear all stored data
    localStorage.removeItem('isLoggedIn');
    localStorage.removeItem('token');
    this.isAuthenticated = false;
    
    // Navigate to login page
    this.router.navigate(['/login']);
  }

  isLoggedIn(): boolean {
    return this.isAuthenticated;
  }

  // Optional: Guard routes with this method
  getAuthStatus(): Observable<boolean> {
    // Here you would typically validate the token with your backend
    return of(this.isAuthenticated);
  }
}