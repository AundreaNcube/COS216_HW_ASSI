import { Injectable } from '@angular/core';
import { Observable, Subject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class WebsocketService {
  private socket!: WebSocket;
  private messageSubject: Subject<any> = new Subject<any>();
  private messageQueue: any[] = [];
  private connected: boolean = false; // Renamed from isConnected
  private isAuthenticated: boolean = false;
  private reconnectAttempts: number = 0;
  private maxReconnectAttempts: number = 5;
  private reconnectInterval: number = 5000;
  private authRetryCount: number = 0;
  private maxAuthRetries: number = 3;

  constructor() {
    this.connect();
    this.startKeepAlive();
  }

  private connect(): void {
    this.socket = new WebSocket('ws://localhost:4494');

    this.socket.onopen = () => {
      this.connected = true;
      this.reconnectAttempts = 0;
      console.log('WebSocket connected');
      this.flushMessageQueue();
    };

    this.socket.onmessage = (event) => {
      const data = JSON.parse(event.data);
      console.log('WebSocket message received:', JSON.stringify(data, null, 2));
      if (data.type === 'login_success') {
        this.isAuthenticated = true;
        this.authRetryCount = 0;
        const currentApiKey = localStorage.getItem('apikey');
        if (data.apikey && data.apikey !== currentApiKey) {
          localStorage.setItem('apikey', data.apikey);
          console.log('Updated apikey from WebSocket:', data.apikey);
        }
        let userType = localStorage.getItem('userType') || 'Distributor';
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
        if (data.userType) {
          const rawUserType = data.userType.toLowerCase();
          userType = userTypeMap[rawUserType] || 'Distributor';
          localStorage.setItem('userType', userType);
          console.log('Set userType from login_success:', userType);
        }
        console.log('Login success, sessionId:', data.sessionId);
        this.flushMessageQueue();
        this.messageSubject.next(data);
      } else if (data.type === 'error') {
        console.error('WebSocket error:', {
          message: data.message,
          command: data.command,
          email: localStorage.getItem('email')
        });
        if (data.message === 'Not authenticated') {
          this.isAuthenticated = false;
          this.messageQueue = [];
          this.messageSubject.next({ type: 'auth_error', message: 'Authentication failed. Please log in again.' });
          this.reAuthenticate();
        } else if (data.message === 'Permission denied') {
          this.messageSubject.next({ type: 'permission_error', message: `Permission denied for ${data.command}` });
        }
        this.messageSubject.next(data);
      } else {
        this.messageSubject.next(data);
      }
    };

    this.socket.onerror = (error) => {
      console.error('WebSocket error:', error);
      this.connected = false;
      this.isAuthenticated = false;
      this.messageSubject.next({ type: 'connection_error', message: 'WebSocket connection failed' });
    };

    this.socket.onclose = () => {
      console.log('WebSocket closed');
      this.connected = false;
      this.isAuthenticated = false;
      this.attemptReconnect();
    };
  }

  public isConnected(): boolean {
    return this.connected && this.socket.readyState === WebSocket.OPEN;
  }

  public reconnect(): void {
    console.log('Public reconnect called');
    this.attemptReconnect();
  }

  private reAuthenticate(): void {
    if (this.authRetryCount >= this.maxAuthRetries) {
      console.error('Max authentication retries reached. Clearing session.');
      this.messageSubject.next({ type: 'auth_error', message: 'Authentication failed after multiple attempts' });
      localStorage.clear();
      return;
    }
    this.authRetryCount++;
    const email = localStorage.getItem('email');
    const password = localStorage.getItem('password');
    if (email && password && this.isConnected()) {
      console.log(`Re-authenticating WebSocket with email: ${email} (Attempt ${this.authRetryCount}/${this.maxAuthRetries})`);
      this.sendMessage({ type: 'login', email, password });
    } else {
      console.warn('Cannot re-authenticate: missing credentials or not connected');
      this.messageSubject.next({ type: 'auth_error', message: 'Authentication credentials missing or connection not ready' });
    }
  }

  private sendMessageWhenReady(message: string): void {
    if (this.isConnected()) {
      console.log('Sending WebSocket message:', message);
      this.socket.send(message);
    } else {
      console.log('WebSocket not ready, queuing message:', message);
      this.messageQueue.push(message);
    }
  }

  private flushMessageQueue(): void {
    if (!this.isConnected() || !this.isAuthenticated) {
      console.log('Cannot flush queue: not connected or authenticated');
      return;
    }
    while (this.messageQueue.length > 0) {
      const message = this.messageQueue.shift();
      console.log('Sending queued WebSocket message:', message);
      this.socket.send(message);
    }
  }

  private attemptReconnect(): void {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      console.log(`Reconnecting WebSocket... Attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts}`);
      setTimeout(() => {
        this.connect();
      }, this.reconnectInterval);
    } else {
      console.error('Max reconnect attempts reached.');
      this.messageSubject.next({ type: 'connection_error', message: 'WebSocket connection failed' });
    }
  }

  private startKeepAlive(): void {
    setInterval(() => {
      if (this.isConnected() && this.isAuthenticated) {
        const apikey = localStorage.getItem('apikey');
        if (!apikey) {
          console.warn('No apikey for keep-alive');
          return;
        }
        this.sendMessage({ type: 'keep_alive', apikey });
      }
    }, 20000);
  }

  public sendMessage(message: any) {
    const apikey = localStorage.getItem('apikey');
    if (!apikey && message.type !== 'login') {
      console.warn('No apikey found, cannot send message:', message);
      this.messageSubject.next({ type: 'auth_error', message: 'Authentication required' });
      return;
    }
    const messageWithAuth = message.type === 'login' ? message : { ...message, apikey };
    const messageString = JSON.stringify(messageWithAuth);
    this.sendMessageWhenReady(messageString);
  }

  public getMessages(): Observable<any> {
    return this.messageSubject.asObservable();
  }
}