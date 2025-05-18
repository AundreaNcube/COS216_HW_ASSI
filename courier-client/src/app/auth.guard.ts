import { Injectable } from '@angular/core';
import { CanActivate, Router } from '@angular/router';

@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {
  constructor(private router: Router) {}

  canActivate(): boolean {
    const apikey = localStorage.getItem('apikey');
    if (apikey) {
      return true;
    }
    this.router.navigate(['/login']);
    return false;
  }
}