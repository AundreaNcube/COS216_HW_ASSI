/* import { Component, Input, OnInit, OnChanges, SimpleChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import * as L from 'leaflet';

@Component({
  selector: 'app-map',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './map.component.html',
  styleUrls: ['./map.component.css']
})
export class MapComponent implements OnInit, OnChanges {
  private map!: L.Map;
  private droneMarkers: { [id: string]: L.Marker } = {};
  private deliveryMarkers: { [id: string]: L.Marker } = {};

  @Input() drones: any[] = [];
  @Input() deliveries: any[] = [];

  constructor() { }

  ngOnInit(): void {
    this.initMap();
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (changes['drones'] || changes['deliveries']) {
      this.updateMap();
    }
  }

  private initMap(): void {
    this.map = L.map('map').setView([-25.7479, 28.2293], 12);

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
      crossOrigin: ''
    }).addTo(this.map);
  }

  private updateMap(): void {
    // Clear existing markers
    Object.values(this.droneMarkers).forEach(marker => this.map.removeLayer(marker));
    Object.values(this.deliveryMarkers).forEach(marker => this.map.removeLayer(marker));
    this.droneMarkers = {};
    this.deliveryMarkers = {};

    // Add drone markers
    this.drones.forEach(drone => {
      if (drone.gps_coordinates && Array.isArray(drone.gps_coordinates) && drone.gps_coordinates.length === 2) {
        const [lat, lng] = drone.gps_coordinates;
        if (this.isValidCoordinate(lat, lng)) {
          this.droneMarkers[drone.id] = L.marker([lat, lng], {
            icon: L.icon({
              iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
              iconSize: [25, 41],
              iconAnchor: [12, 41],
              popupAnchor: [1, -34]
            })
          }).addTo(this.map)
            .bindPopup(`<b>Drone #${drone.id}</b><br>Battery: ${drone.battery_level}%<br>Status: ${drone.is_available ? 'Available' : 'In Use'}`);
        } else {
          console.warn(`Invalid drone coordinates for drone ${drone.id}: [${lat}, ${lng}]`);
        }
      } else {
        console.warn(`Missing or invalid gps_coordinates for drone ${drone.id}:`, drone.gps_coordinates);
      }
    });

    // Add delivery markers
    this.deliveries.forEach(delivery => {
      if (delivery.destination && Array.isArray(delivery.destination) && delivery.destination.length === 2) {
        const [lat, lng] = delivery.destination;
        if (this.isValidCoordinate(lat, lng)) {
          this.deliveryMarkers[delivery.order_id] = L.marker([lat, lng], {
            icon: L.icon({
              iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
              iconSize: [38, 61],
              iconAnchor: [19, 61],
              popupAnchor: [1, -34]
            })
          }).addTo(this.map)
            .bindPopup(`<b>Order #${delivery.order_id}</b><br>Status: ${delivery.state || 'Delivering'}`);
        } else {
          console.warn(`Invalid delivery coordinates for order ${delivery.order_id}: [${lat}, ${lng}]`);
        }
      } else {
        console.warn(`Missing or invalid destination for order ${delivery.order_id}:`, delivery.destination);
      }
    });

    // Fit map to bounds if markers exist
    const allMarkers = [...Object.values(this.droneMarkers), ...Object.values(this.deliveryMarkers)];
    if (allMarkers.length > 0) {
      const group = L.featureGroup(allMarkers);
      this.map.fitBounds(group.getBounds().pad(0.2));
    } else {
      console.log('No valid markers to display on map');
    }
  }

  private isValidCoordinate(lat: number, lng: number): boolean {
    return typeof lat === 'number' && typeof lng === 'number' &&
           lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180 &&
           !isNaN(lat) && !isNaN(lng);
  }
} */

  import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import * as L from 'leaflet';

@Component({
  selector: 'app-map',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './map.component.html',
  styleUrls: ['./map.component.css']
})
export class MapComponent implements OnInit {
  private map!: L.Map;
  private headquartersMarker!: L.Marker;

  constructor() { }

  ngOnInit(): void {
    this.initMap();
  }

  private initMap(): void {
    // Initialize map centered on Hatfield, Pretoria
    this.map = L.map('map').setView([-25.7472, 28.2511], 14);

    // Add OpenStreetMap tile layer
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
      crossOrigin: ''
    }).addTo(this.map);

    // Add Headquarters marker
    this.headquartersMarker = L.marker([-25.7472, 28.2511], {
      icon: L.icon({
        iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
        iconSize: [25, 41],
        iconAnchor: [12, 41],
        popupAnchor: [1, -34]
      })
    }).addTo(this.map)
      .bindPopup('<b>Headquarters</b>')
      .openPopup(); // Automatically open the popup
  }
}