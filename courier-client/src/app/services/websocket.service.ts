import { Injectable } from '@angular/core';
import { Observable, Subject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class WebsocketService {
  private socket: WebSocket;
  private messageSubject: Subject<any> = new Subject<any>();

  constructor() {
    this.socket = new WebSocket('ws://localhost:4494');
    this.socket.onmessage = (event) => {
      this.messageSubject.next(JSON.parse(event.data));
    };
    this.socket.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
  }

  sendMessage(message: any) {
    this.socket.send(JSON.stringify(message));
  }

  getMessages(): Observable<any> {
    return this.messageSubject.asObservable();
  }
}