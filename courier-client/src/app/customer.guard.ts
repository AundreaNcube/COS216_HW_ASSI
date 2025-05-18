import { Injectable } from '@angular/core';
import { CanActivate, Router } from '@angular/router';

@Injectable({
  providedIn: 'root'
})
export class CustomerGuard implements CanActivate {
  constructor(private router: Router) {}

  canActivate(): boolean {
    const userType = localStorage.getItem('userType');
    const apikey = localStorage.getItem('apikey');

    if (!apikey) {
      this.router.navigate(['/login']);
      return false;
    }

    if (userType === 'Customer') {
      return true;
    }

    this.router.navigate(['/dashboard']);
    return false;
  }
}