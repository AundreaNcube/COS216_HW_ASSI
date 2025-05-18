import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { WebsocketService } from '../services/websocket.service';
import { Router } from '@angular/router';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { MapComponent } from '../map/map.component';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, FormsModule, MapComponent],
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.css']
})
export class DashboardComponent implements OnInit, OnDestroy {
  userType: string = localStorage.getItem('userType') || '';
  orders: any[] = [];
  drones: any[] = [];
  deliveryRequests: any[] = [];
  deliveringOrders: any[] = [];
  selectedOrderId: number | null = null;
  selectedDroneId: number | null = null;
  errorMessage: string = '';
  currencyChoice: string = localStorage.getItem('currency') || 'ZAR';
  currencyRates = JSON.parse(localStorage.getItem('exchangeRates') || '{"ZAR":18.4380836589,"USD":1,"EUR":0.9706301545}');
  shipping: number = 175;
  taxRate: number = 0.27;
  isRequestingDelivery: boolean = false;
  private isAuthenticated: boolean = false;
  private maxWebSocketRetries: number = 3;
  private webSocketRetryCount: number = 0;
  private webSocketRetryInterval: number = 2000;
  private dronePollingInterval: any = null;

  constructor(
    private websocketService: WebsocketService,
    private router: Router,
    private http: HttpClient
  ) {}

  ngOnInit(): void {
    console.log('Dashboard ngOnInit started', {
      apikey: localStorage.getItem('apikey') ? '[SET]' : 'MISSING',
      userType: localStorage.getItem('userType'),
      email: localStorage.getItem('email')
    });

    const validUserTypes = ['Customer', 'Courier', 'Distributor'];
    this.userType = localStorage.getItem('userType') || '';
    const normalizedUserType = this.userType ? this.userType.charAt(0).toUpperCase() + this.userType.slice(1).toLowerCase() : '';

    if (!localStorage.getItem('apikey') || !validUserTypes.includes(normalizedUserType)) {
      console.warn('Authentication check failed:', {
        userType: this.userType,
        normalizedUserType,
        apikey: localStorage.getItem('apikey') ? '[SET]' : 'MISSING'
      });
      localStorage.clear();
      this.router.navigate(['/login']);
      return;
    }
    this.userType = normalizedUserType;
    localStorage.setItem('userType', this.userType);
    console.log('Normalized userType:', this.userType);

    this.isAuthenticated = !!localStorage.getItem('apikey');
    if (this.isAuthenticated) {
      if (!this.websocketService.isConnected()) {
        console.log('WebSocket not connected, attempting reconnect');
        this.websocketService.reconnect();
      }
      this.fetchData();
      if (this.userType === 'Courier' || this.userType === 'Distributor') {
        this.startDroneStatusPolling();
      }
    }

    this.websocketService.getMessages().subscribe({
      next: (message) => {
        console.log('WebSocket message received:', JSON.stringify(message, null, 2));
        if (message.type === 'login_success') {
          console.log('WebSocket login_success:', {
            sessionId: message.sessionId,
            userType: message.userType
          });
          this.isAuthenticated = true;
          this.webSocketRetryCount = 0;
          if (message.userType) {
            const userType = message.userType.charAt(0).toUpperCase() + message.userType.slice(1).toLowerCase();
            this.userType = userType;
            localStorage.setItem('userType', userType);
            console.log('Updated userType from server:', userType);
          }
          this.fetchData();
          if (this.userType === 'Courier' || this.userType === 'Distributor') {
            this.startDroneStatusPolling();
          }
        } else if (message.type === 'orders') {
          this.orders = message.data?.map((order: any) => ({
            ...order,
            isValid: Array.isArray(order.products) && order.products.length > 0
          })) || [];
          console.log('Orders received:', this.orders);
          this.errorMessage = this.orders.length === 0 ? 'No orders available.' : '';
          this.logButtonState();
        } else if (message.type === 'drone_status') {
          this.drones = message.data || [];
          console.log('Drones received:', this.drones);
          this.errorMessage = this.drones.length === 0 ? 'No drones available.' : '';
          if (this.selectedDroneId && !this.drones.find(d => d.id === this.selectedDroneId)) {
            this.selectedDroneId = null;
            this.selectedOrderId = null;
          }
          this.logButtonState();
        } else if (message.type === 'delivery_requests') {
          this.deliveryRequests = message.data || [];
          console.log('Delivery requests received:', this.deliveryRequests);
          this.errorMessage = this.deliveryRequests.length === 0 ? 'No delivery requests available.' : '';
          this.logButtonState();
        } else if (message.type === 'currently_delivering') {
          this.deliveringOrders = message.data || [];
          console.log('Delivering orders received:', this.deliveringOrders);
          this.errorMessage = this.deliveringOrders.length === 0 ? 'No orders currently delivering.' : '';
        } else if (message.type === 'command_result') {
          console.log('Command result:', message);
          this.isRequestingDelivery = false;
          if (message.status === 'success') {
            this.errorMessage = message.message || 'Action completed successfully.';
            if (message.message.includes('Delivery started')) {
              this.fetchCurrentlyDelivering();
              this.fetchDrones();
              this.fetchDeliveryRequests();
              this.selectedOrderId = null;
              this.selectedDroneId = null;
            } else if (message.message.includes('Delivery request')) {
              this.fetchDeliveryRequests();
            }
          } else {
            this.errorMessage = message.message || 'Action failed.';
          }
          this.logButtonState();
        } else if (message.type === 'notification') {
          console.log('Notification:', message.message);
          this.errorMessage = message.message;
          if (message.message.includes('delivery')) {
            this.fetchCurrentlyDelivering();
            this.fetchOrders();
            this.fetchDrones();
          }
        } else if (message.type === 'error') {
          console.error('WebSocket error:', {
            message: message.message,
            command: message.command
          });
          this.isRequestingDelivery = false;
          this.errorMessage = message.message;
          if (message.message === 'Not authenticated') {
            this.isAuthenticated = false;
            localStorage.clear();
            this.router.navigate(['/login']);
          } else if (message.message === 'Permission denied') {
            this.errorMessage = `You do not have permission to perform this action: ${message.command || 'Unknown'}`;
          }
          this.logButtonState();
        } else if (message.type === 'auth_error') {
          this.isAuthenticated = false;
          this.isRequestingDelivery = false;
          localStorage.clear();
          this.router.navigate(['/login']);
        }
      },
      error: (error: any) => {
        console.error('WebSocket subscription error:', JSON.stringify(error, null, 2));
        this.errorMessage = 'Real-time updates unavailable. Loading data via HTTP.';
        this.isRequestingDelivery = false;
        this.tryFetchDataWithRetry();
        this.logButtonState();
      }
    });
  }

  ngOnDestroy(): void {
    if (this.dronePollingInterval) {
      console.log('Clearing drone polling interval');
      clearInterval(this.dronePollingInterval);
    }
  }

  private startDroneStatusPolling(): void {
    if (this.dronePollingInterval) {
      clearInterval(this.dronePollingInterval);
    }
    console.log('Starting drone status polling');
    this.fetchDrones();
    this.dronePollingInterval = setInterval(() => {
      if (this.isAuthenticated) {
        console.log('Polling drones');
        this.fetchDrones();
      }
    }, 30000);
  }

  private tryFetchDataWithRetry(): void {
    if (this.webSocketRetryCount >= this.maxWebSocketRetries) {
      console.warn('Max WebSocket retries reached, using HTTP fallback');
      this.fetchDataFallback();
      return;
    }
    this.webSocketRetryCount++;
    console.log(`Attempting to fetch data (Retry ${this.webSocketRetryCount}/${this.maxWebSocketRetries})`);
    setTimeout(() => {
      this.fetchData();
    }, this.webSocketRetryInterval);
  }

  fetchData(): void {
    if (!this.isAuthenticated) {
      console.warn('Not authenticated, cannot fetch data');
      this.fetchDataFallback();
      return;
    }
    console.log('Fetching data for userType:', this.userType);
    if (['Customer', 'Courier'].includes(this.userType)) {
      this.fetchOrders();
      this.fetchCurrentlyDelivering();
    }
    if (this.userType === 'Courier' || this.userType === 'Distributor') {
      this.fetchDrones();
      this.fetchDeliveryRequests();
    }
  }

  private fetchDataFallback(): void {
    console.log('Fetching data via fallback for userType:', this.userType);
    const apikey = localStorage.getItem('apikey');
    if (!apikey) {
      this.errorMessage = 'No API key available for data fetch. Please log in again.';
      localStorage.clear();
      this.router.navigate(['/login']);
      return;
    }
    if (['Customer', 'Courier'].includes(this.userType)) {
      this.http
        .post(
          'http://localhost/COS216_HW_ASSI/api2.php',
          { type: 'GetAllOrders', apikey },
          {
            headers: new HttpHeaders({
              'Content-Type': 'application/json',
              'Authorization': 'Basic ' + btoa('u23539764:Keamogetse49')
            })
          }
        )
        .subscribe({
          next: (response: any) => {
            this.orders = response.data
              ?.map((order: any) => ({
                ...order,
                isValid: Array.isArray(order.products) && order.products.length > 0
              })) || [];
            console.log('Fallback orders received:', this.orders);
            this.errorMessage = this.orders.length === 0 ? 'No orders available.' : '';
            this.logButtonState();
          },
          error: (error: any) => {
            console.error('Fallback orders fetch failed:', error);
            this.errorMessage = 'Failed to load orders. Please try again later.';
          }
        });

      this.http
        .post(
          'http://localhost/COS216_HW_ASSI/api2.php',
          { type: 'CurrentlyDelivering', apikey },
          {
            headers: new HttpHeaders({
              'Content-Type': 'application/json',
              'Authorization': 'Basic ' + btoa('u23539764:Keamogetse49')
            })
          }
        )
        .subscribe({
          next: (response: any) => {
            this.deliveringOrders = response.data || [];
            console.log('Fallback delivering orders received:', this.deliveringOrders);
            this.errorMessage = this.deliveringOrders.length === 0 ? 'No orders currently delivering.' : '';
          },
          error: (error: any) => {
            console.error('Fallback delivering orders fetch failed:', error);
            this.errorMessage = 'Failed to load delivering orders. Please try again later.';
          }
        });
    }
    if (this.userType === 'Courier' || this.userType === 'Distributor') {
      this.http
        .post(
          'http://localhost/COS216_HW_ASSI/api2.php',
          { type: 'GetAllDrones', apikey },
          {
            headers: new HttpHeaders({
              'Content-Type': 'application/json',
              'Authorization': 'Basic ' + btoa('u23539764:Keamogetse49')
            })
          }
        )
        .subscribe({
          next: (response: any) => {
            this.drones = response.data || [];
            console.log('Fallback drones received:', this.drones);
            this.errorMessage = this.drones.length === 0 ? 'No drones available.' : '';
            this.logButtonState();
          },
          error: (error: any) => {
            console.error('Fallback drones fetch failed:', error);
            this.errorMessage = 'Failed to load drones. Please try again later.';
          }
        });

      this.http
        .post(
          'http://localhost/COS216_HW_ASSI/api2.php',
          { type: 'GetDeliveryRequests', apikey },
          {
            headers: new HttpHeaders({
              'Content-Type': 'application/json',
              'Authorization': 'Basic ' + btoa('u23539764:Keamogetse49')
            })
          }
        )
        .subscribe({
          next: (response: any) => {
            this.deliveryRequests = response.data || [];
            console.log('Fallback delivery requests received:', this.deliveryRequests);
            this.errorMessage = this.drones.length === 0 ? 'No delivery requests available.' : '';
            this.logButtonState();
          },
          error: (error: any) => {
            console.error('Fallback delivery requests fetch failed:', error);
            this.errorMessage = 'Failed to load delivery requests. Please try again later.';
          }
        });
    }
  }

  fetchOrders(): void {
    this.websocketService.sendMessage({
      type: 'command',
      command: 'GET_ORDERS',
      apikey: localStorage.getItem('apikey')
    });
  }

  fetchDrones(): void {
    console.log('Sending DRONE_STATUS command with apikey:', localStorage.getItem('apikey') ? '[SET]' : 'MISSING');
    this.websocketService.sendMessage({
      type: 'command',
      command: 'DRONE_STATUS',
      apikey: localStorage.getItem('apikey')
    });
  }

  fetchDeliveryRequests(): void {
    this.websocketService.sendMessage({
      type: 'command',
      command: 'GET_DELIVERY_REQUESTS',
      apikey: localStorage.getItem('apikey')
    });
  }

  fetchCurrentlyDelivering(): void {
    this.websocketService.sendMessage({
      type: 'command',
      command: 'CURRENTLY_DELIVERING',
      apikey: localStorage.getItem('apikey')
    });
  }

  refreshDrones(): void {
    console.log('Manually refreshing drones');
    this.fetchDrones();
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
    if (!order || !order.isValid) {
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
    if (!order || !order.isValid) {
      return 0;
    }
    return this.getOrderSubtotal(order) * this.taxRate;
  }

  getOrderTotal(order: any): number {
    if (!order || !order.isValid) {
      return 0;
    }
    return this.getOrderSubtotal(order) + this.shipping + this.getOrderTax(order);
  }

  requestDelivery(): void {
    this.isRequestingDelivery = true;
    this.errorMessage = '';
    console.log('Request delivery initiated:', { userType: this.userType, selectedOrderId: this.selectedOrderId, selectedDroneId: this.selectedDroneId });

    setTimeout(() => {
      if (this.isRequestingDelivery) {
        console.warn('Request delivery timed out');
        this.isRequestingDelivery = false;
        this.errorMessage = 'Delivery request timed out. Please try again.';
        this.logButtonState();
      }
    }, 10000);

    if (this.userType === 'Customer') {
      if (!this.selectedOrderId) {
        this.errorMessage = 'Please select an order';
        console.warn('Request delivery failed: No order selected');
        this.isRequestingDelivery = false;
        this.logButtonState();
        return;
      }
      const message = {
        type: 'command',
        command: 'REQUEST_DELIVERY',
        order_id: this.selectedOrderId,
        apikey: localStorage.getItem('apikey')
      };
      console.log('Sending REQUEST_DELIVERY:', message);
      this.websocketService.sendMessage(message);
    } else if (this.userType === 'Courier' || this.userType === 'Distributor') {
      if (!this.selectedOrderId) {
        this.errorMessage = 'Please select an order';
        console.warn('Start delivery failed: No order selected');
        this.isRequestingDelivery = false;
        this.logButtonState();
        return;
      }
      if (!this.selectedDroneId) {
        this.errorMessage = 'Please select a drone';
        console.warn('Start delivery failed: No drone selected');
        this.isRequestingDelivery = false;
        this.logButtonState();
        return;
      }
      const drone = this.drones.find(d => d.id === this.selectedDroneId);
      if (!drone) {
        this.errorMessage = 'Selected drone not found';
        console.warn('Start delivery failed: Drone not found', { droneId: this.selectedDroneId });
        this.isRequestingDelivery = false;
        this.logButtonState();
        return;
      }
      if (drone.order_id && drone.order_id !== this.selectedOrderId) {
        this.errorMessage = `Drone ${drone.id} is linked to order ${drone.order_id}`;
        console.warn('Start delivery failed: Drone linked to another order', { droneId: drone.id, linkedOrderId: drone.order_id });
        this.isRequestingDelivery = false;
        this.logButtonState();
        return;
      }
      if (!drone.is_available) {
        this.errorMessage = `Drone ${drone.id} is not available`;
        console.warn('Start delivery failed: Drone not available', { droneId: drone.id });
        this.isRequestingDelivery = false;
        this.logButtonState();
        return;
      }
      const message = {
        type: 'command',
        command: 'START_DELIVERY',
        order_id: this.selectedOrderId,
        drone_id: this.selectedDroneId,
        apikey: localStorage.getItem('apikey')
      };
      console.log('Sending START_DELIVERY:', message);
      this.websocketService.sendMessage(message);
    }
  }

  selectOrder(orderId: number): void {
    this.selectedOrderId = this.selectedOrderId === orderId ? null : orderId;
    this.errorMessage = '';
    console.log('Selected order:', this.selectedOrderId);
    this.logButtonState();
  }

  selectDrone(droneId: number | null): void {
    this.selectedDroneId = this.selectedDroneId === droneId ? null : droneId;
    this.errorMessage = '';
    console.log('Selected drone:', this.selectedDroneId);
    if (this.selectedDroneId) {
      const drone = this.drones.find(d => d.id === this.selectedDroneId);
      if (drone) {
        if (drone.order_id) {
          this.selectedOrderId = drone.order_id;
          console.log('Auto-selected order:', this.selectedOrderId);
        }
        console.log('Drone details:', { id: drone.id, is_available: drone.is_available, linked_order: drone.order_id });
      } else {
        this.errorMessage = 'Selected drone not found';
        console.warn('Drone not found:', this.selectedDroneId);
      }
    } else {
      if (!this.deliveryRequests.some(r => r.order_id === this.selectedOrderId)) {
        this.selectedOrderId = null;
      }
    }
    this.logButtonState();
  }

  isDroneAvailable(): boolean {
    if (!this.selectedDroneId) {
      console.log('isDroneAvailable: false (no drone selected)');
      return false;
    }
    const drone = this.drones.find(d => d.id === this.selectedDroneId);
    const isAvailable = !!drone && drone.is_available && (!drone.order_id || drone.order_id === this.selectedOrderId);
    console.log('isDroneAvailable:', isAvailable, { drone: drone ? drone.id : null, is_available: drone?.is_available, order_id: drone?.order_id });
    return isAvailable;
  }

  logButtonState(): void {
    console.log('Button state:', {
      selectedOrderId: this.selectedOrderId,
      selectedDroneId: this.selectedDroneId,
      isRequestingDelivery: this.isRequestingDelivery,
      isDroneAvailable: this.isDroneAvailable(),
      dronesCount: this.drones.length
    });
  }

  logout(): void {
    if (this.dronePollingInterval) {
      clearInterval(this.dronePollingInterval);
    }
    localStorage.clear();
    this.router.navigate(['/login']);
  }
}