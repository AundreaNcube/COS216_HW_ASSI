import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { LoginComponent } from './login/login.component';  // Updated path to match typical project structure

const routes: Routes = [
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },  // Redirect root to dashboard
  { path: 'login', component: LoginComponent },
  // Add other routes as needed
  // { path: 'dashboard', component: DashboardComponent },
  // { path: 'profile', component: ProfileComponent },
  { path: '**', redirectTo: 'dashboard' }  // Catch all route for invalid paths
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }