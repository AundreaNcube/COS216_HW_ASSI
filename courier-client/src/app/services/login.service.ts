import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError, map } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class LoginService {
  private apiUrl = 'http://localhost/COS216_HW_ASSI/api2.php'; // Use proxy path
  private authCredentials = { username: 'u23539764', password: 'Keamogetse49' };

  constructor(private http: HttpClient) {}

  login(email: string, password: string): Observable<any> {
    console.log('Sending login request:', { email, password: '[REDACTED]', apiUrl: this.apiUrl });
    const body = { type: 'Login', email, password };
    const headers = new HttpHeaders({
      'Content-Type': 'application/json',
      Authorization: 'Basic ' + btoa(`${this.authCredentials.username}:${this.authCredentials.password}`),
      'X-Requested-With': 'XMLHttpRequest'
    });
    return this.http.post(this.apiUrl, body, { headers }).pipe(
      map((response: any) => {
        console.log('Raw login API response:', JSON.stringify(response, null, 2));
        if (response.status === 'error') {
          console.warn('API returned error:', response.data);
          throw new Error(response.data || 'Login failed');
        }
        if (!response.data.apikey) {
          console.warn('API response missing apikey:', response);
          throw new Error('Invalid response: apikey missing');
        }
        const rawUserType = (response.data.user_type || 'operator').toLowerCase();
        const userTypeMap: { [key: string]: string } = {
          customer: 'Customer',
          courier: 'Courier',
          delivery: 'Courier',
          distributor: 'Distributor',
          operator: 'Distributor',
          admin: 'Distributor',
          manager: 'Distributor',
          supervisor: 'Distributor',
          administrator: 'Distributor'
        };
        const userType = userTypeMap[rawUserType] || 'Distributor';
        const result = {
          apikey: response.data.apikey,
          userType,
          name: response.data.name,
          surname: response.data.surname
        };
        console.log('Parsed login response:', result);
        return result;
      }),
      catchError((error) => {
        console.error('Login service error:', {
          message: error.message,
          status: error.status,
          statusText: error.statusText,
          url: error.url,
          name: error.name,
          email
        });
        let errorMessage = error.message || 'Server error';
        if (error.status === 0 && error.message.includes('Http failure')) {
          errorMessage = 'CORS error or server unreachable. Check server CORS configuration or network connectivity.';
        }
        return throwError(() => new Error(errorMessage));
      })
    );
  }
}