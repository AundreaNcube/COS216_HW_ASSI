import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { WebsocketService } from '../services/websocket.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-orders',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './orders.component.html',
  styleUrls: ['./orders.component.css']
})
export class OrdersComponent implements OnInit {
  orders: any[] = [];
  errorMessage: string = '';
  currencyChoice: string = localStorage.getItem('currency') || 'ZAR';
  currencyRates = JSON.parse(localStorage.getItem('exchangeRates') || '{"ZAR":18.4380836589,"USD":1,"EUR":0.9706301545}');
  shipping: number = 175;
  taxRate: number = 0.27;
  loading: boolean = false;

  constructor(private websocketService: WebsocketService, private router: Router) {}

  ngOnInit(): void {
    if (!localStorage.getItem('apikey')) {
      this.router.navigate(['/login']);
      return;
    }
    this.loading = true;
    this.websocketService.getMessages().subscribe({
      next: (message) => {
        if (message.type === 'orders') {
          this.orders = message.data.filter((order: any) => order.state === 'Storage');
          this.loading = false;
          console.log('Orders received:', this.orders);
        } else if (message.type === 'error') {
          this.errorMessage = message.message;
          this.loading = false;
          console.error('Error:', message.message);
          if (message.message.includes('Invalid API key')) {
            localStorage.removeItem('apikey');
            localStorage.removeItem('userType');
            this.router.navigate(['/login']);
          }
        }
      },
      error: (error) => {
        this.errorMessage = 'WebSocket error';
        this.loading = false;
        console.error('WebSocket error:', error);
      }
    });
    this.fetchOrders();
    this.fetchCurrencies();
  }

  fetchOrders(): void {
    this.websocketService.sendMessage({ command: 'GET_ORDERS', apikey: localStorage.getItem('apikey') });
  }

fetchCurrencies(): void {
    const apikey = localStorage.getItem('apikey');
    if (!apikey) {
      console.error('No apikey found for currency fetch');
      return;
    }
    const payload = { type: 'GetCurrencyList', apikey };
    console.log('Sending currency request:', payload);
    fetch('//wsl.localhost/Ubuntu-22.04/home/xampp/htdocs/COS216_HW_ASSI/api2.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
      .then(response => {
        console.log('Currency response status:', response.status);
        if (!response.ok) {
          throw new Error(`HTTP error ${response.status}`);
        }
        return response.json();
      })
      .then(response => {
        console.log('Currency response:', response);
        if (response.status === 'success') {
          this.currencyRates = response.data;
          localStorage.setItem('exchangeRates', JSON.stringify(this.currencyRates));
        } else {
          console.error('Currency fetch failed:', response);
        }
      })
      .catch(error => console.error('Error fetching currencies:', error));
  }

  convertPrice(priceInZAR: number): string {
    priceInZAR = parseFloat(priceInZAR.toString()) || 0;
    if (this.currencyChoice === 'ZAR' || !this.currencyRates[this.currencyChoice]) {
      return priceInZAR.toFixed(2);
    }
    const convertedPrice = (priceInZAR / this.currencyRates['ZAR']) * this.currencyRates[this.currencyChoice];
    return convertedPrice.toFixed(2);
  }

  formatTitle(title: string): string {
    if (!title) return '';
    return title
      .replace(/[^\w\s-]/g, '')
      .replace(/\s+/g, ' ')
      .replace(/(^\w|\s\w)/g, (m) => m.toUpperCase())
      .trim();
  }

getOrderSubtotal(order: any): number {
    if (!order || !Array.isArray(order.products)) {
      console.warn('Invalid order or products array:', order);
      return 0;
    }
    return order.products.reduce((sum: number, item: any) => {
      const price = item.final_price || 0;
      const quantity = item.quantity || 1;
      return sum + price * quantity;
    }, 0);
  }

  getOrderTax(order: any): number {
    return this.getOrderSubtotal(order) * this.taxRate;
  }

  getOrderTotal(order: any): number {
    return this.getOrderSubtotal(order) + this.shipping + this.getOrderTax(order);
  }
}