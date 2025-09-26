#!/usr/bin/env python3
"""
Naebak Messaging Service - Routing System
=========================================

Advanced routing system for the messaging service with load balancing,
health checking, and service discovery capabilities.

Features:
- Dynamic route registration
- Load balancing algorithms
- Health monitoring
- Circuit breaker pattern
- Request forwarding
- Service discovery
- Rate limiting per route
"""

import time
import random
import requests
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from flask import request, jsonify, g
from functools import wraps
import logging

logger = logging.getLogger(__name__)

class ServiceRegistry:
    """Service registry for managing available services"""
    
    def __init__(self):
        self.services = defaultdict(list)
        self.health_status = {}
        self.last_health_check = {}
        self.lock = threading.RLock()
    
    def register_service(self, service_name, host, port, health_endpoint='/health'):
        """Register a service instance"""
        service_url = f"http://{host}:{port}"
        service_info = {
            'url': service_url,
            'host': host,
            'port': port,
            'health_endpoint': health_endpoint,
            'registered_at': datetime.utcnow(),
            'weight': 1.0,
            'active_connections': 0
        }
        
        with self.lock:
            if service_info not in self.services[service_name]:
                self.services[service_name].append(service_info)
                self.health_status[f"{service_name}:{service_url}"] = True
                logger.info(f"Registered service {service_name} at {service_url}")
    
    def unregister_service(self, service_name, host, port):
        """Unregister a service instance"""
        service_url = f"http://{host}:{port}"
        
        with self.lock:
            self.services[service_name] = [
                s for s in self.services[service_name] 
                if s['url'] != service_url
            ]
            self.health_status.pop(f"{service_name}:{service_url}", None)
            self.last_health_check.pop(f"{service_name}:{service_url}", None)
            logger.info(f"Unregistered service {service_name} at {service_url}")
    
    def get_healthy_services(self, service_name):
        """Get list of healthy service instances"""
        with self.lock:
            healthy_services = []
            for service in self.services[service_name]:
                service_key = f"{service_name}:{service['url']}"
                if self.health_status.get(service_key, False):
                    healthy_services.append(service)
            return healthy_services
    
    def update_health_status(self, service_name, service_url, is_healthy):
        """Update health status of a service"""
        service_key = f"{service_name}:{service_url}"
        with self.lock:
            self.health_status[service_key] = is_healthy
            self.last_health_check[service_key] = datetime.utcnow()

class LoadBalancer:
    """Load balancer with multiple algorithms"""
    
    def __init__(self):
        self.round_robin_counters = defaultdict(int)
        self.connection_counts = defaultdict(int)
    
    def round_robin(self, services):
        """Round-robin load balancing"""
        if not services:
            return None
        
        service_key = id(services)
        index = self.round_robin_counters[service_key] % len(services)
        self.round_robin_counters[service_key] += 1
        return services[index]
    
    def least_connections(self, services):
        """Least connections load balancing"""
        if not services:
            return None
        
        min_connections = float('inf')
        selected_service = None
        
        for service in services:
            connections = service.get('active_connections', 0)
            if connections < min_connections:
                min_connections = connections
                selected_service = service
        
        return selected_service
    
    def weighted_random(self, services):
        """Weighted random load balancing"""
        if not services:
            return None
        
        total_weight = sum(service.get('weight', 1.0) for service in services)
        if total_weight == 0:
            return random.choice(services)
        
        random_weight = random.uniform(0, total_weight)
        current_weight = 0
        
        for service in services:
            current_weight += service.get('weight', 1.0)
            if random_weight <= current_weight:
                return service
        
        return services[-1]  # Fallback
    
    def health_aware(self, services):
        """Health-aware load balancing (prefers healthier services)"""
        if not services:
            return None
        
        # Sort by health score (you can implement more sophisticated health scoring)
        healthy_services = [s for s in services if s.get('health_score', 1.0) > 0.5]
        if healthy_services:
            return self.weighted_random(healthy_services)
        
        return self.weighted_random(services)

class CircuitBreaker:
    """Circuit breaker pattern implementation"""
    
    def __init__(self, failure_threshold=5, recovery_timeout=60, expected_exception=Exception):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
        self.lock = threading.RLock()
    
    def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection"""
        with self.lock:
            if self.state == 'OPEN':
                if self._should_attempt_reset():
                    self.state = 'HALF_OPEN'
                else:
                    raise Exception("Circuit breaker is OPEN")
            
            try:
                result = func(*args, **kwargs)
                self._on_success()
                return result
            except self.expected_exception as e:
                self._on_failure()
                raise e
    
    def _should_attempt_reset(self):
        """Check if we should attempt to reset the circuit breaker"""
        return (
            self.last_failure_time and
            datetime.utcnow() - self.last_failure_time >= timedelta(seconds=self.recovery_timeout)
        )
    
    def _on_success(self):
        """Handle successful call"""
        self.failure_count = 0
        self.state = 'CLOSED'
    
    def _on_failure(self):
        """Handle failed call"""
        self.failure_count += 1
        self.last_failure_time = datetime.utcnow()
        
        if self.failure_count >= self.failure_threshold:
            self.state = 'OPEN'

class RateLimiter:
    """Rate limiter for API endpoints"""
    
    def __init__(self):
        self.requests = defaultdict(deque)
        self.lock = threading.RLock()
    
    def is_allowed(self, key, limit, window_seconds):
        """Check if request is allowed under rate limit"""
        now = time.time()
        window_start = now - window_seconds
        
        with self.lock:
            # Remove old requests outside the window
            while self.requests[key] and self.requests[key][0] < window_start:
                self.requests[key].popleft()
            
            # Check if under limit
            if len(self.requests[key]) < limit:
                self.requests[key].append(now)
                return True
            
            return False

class RoutingSystem:
    """Main routing system class"""
    
    def __init__(self, app=None):
        self.app = app
        self.service_registry = ServiceRegistry()
        self.load_balancer = LoadBalancer()
        self.circuit_breakers = {}
        self.rate_limiter = RateLimiter()
        self.routes = {}
        self.middleware = []
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize routing system with Flask app"""
        self.app = app
        
        # Start health check thread
        health_thread = threading.Thread(target=self._health_check_loop, daemon=True)
        health_thread.start()
        
        # Register default routes
        self._register_default_routes()
    
    def register_route(self, path, service_name, methods=['GET'], 
                      load_balance_algorithm='round_robin',
                      rate_limit=None, circuit_breaker_config=None):
        """Register a route with the routing system"""
        route_config = {
            'service_name': service_name,
            'methods': methods,
            'load_balance_algorithm': load_balance_algorithm,
            'rate_limit': rate_limit,
            'circuit_breaker_config': circuit_breaker_config or {}
        }
        
        self.routes[path] = route_config
        
        # Create circuit breaker if configured
        if circuit_breaker_config:
            cb_key = f"{service_name}:{path}"
            self.circuit_breakers[cb_key] = CircuitBreaker(**circuit_breaker_config)
        
        logger.info(f"Registered route {path} -> {service_name}")
    
    def add_middleware(self, middleware_func):
        """Add middleware function"""
        self.middleware.append(middleware_func)
    
    def route_request(self, path, method='GET'):
        """Route a request to appropriate service"""
        # Apply middleware
        for middleware in self.middleware:
            result = middleware(request)
            if result:
                return result
        
        # Find matching route
        route_config = self.routes.get(path)
        if not route_config:
            return jsonify({'error': 'Route not found'}), 404
        
        if method not in route_config['methods']:
            return jsonify({'error': 'Method not allowed'}), 405
        
        # Apply rate limiting
        if route_config['rate_limit']:
            client_ip = request.remote_addr
            limit_config = route_config['rate_limit']
            
            if not self.rate_limiter.is_allowed(
                f"{client_ip}:{path}",
                limit_config['requests'],
                limit_config['window']
            ):
                return jsonify({'error': 'Rate limit exceeded'}), 429
        
        # Get service instance
        service_name = route_config['service_name']
        healthy_services = self.service_registry.get_healthy_services(service_name)
        
        if not healthy_services:
            return jsonify({'error': 'Service unavailable'}), 503
        
        # Select service using load balancing
        algorithm = route_config['load_balance_algorithm']
        if algorithm == 'round_robin':
            selected_service = self.load_balancer.round_robin(healthy_services)
        elif algorithm == 'least_connections':
            selected_service = self.load_balancer.least_connections(healthy_services)
        elif algorithm == 'weighted_random':
            selected_service = self.load_balancer.weighted_random(healthy_services)
        elif algorithm == 'health_aware':
            selected_service = self.load_balancer.health_aware(healthy_services)
        else:
            selected_service = self.load_balancer.round_robin(healthy_services)
        
        if not selected_service:
            return jsonify({'error': 'No available service instance'}), 503
        
        # Forward request with circuit breaker protection
        try:
            cb_key = f"{service_name}:{path}"
            circuit_breaker = self.circuit_breakers.get(cb_key)
            
            if circuit_breaker:
                response = circuit_breaker.call(self._forward_request, selected_service, path, method)
            else:
                response = self._forward_request(selected_service, path, method)
            
            return response
            
        except Exception as e:
            logger.error(f"Request forwarding failed: {str(e)}")
            return jsonify({'error': 'Service request failed'}), 502
    
    def _forward_request(self, service, path, method):
        """Forward request to selected service"""
        service_url = service['url']
        target_url = f"{service_url}{path}"
        
        # Increment connection count
        service['active_connections'] = service.get('active_connections', 0) + 1
        
        try:
            # Prepare request data
            headers = dict(request.headers)
            headers.pop('Host', None)  # Remove host header
            
            # Forward request
            if method == 'GET':
                response = requests.get(
                    target_url,
                    params=request.args,
                    headers=headers,
                    timeout=30
                )
            elif method == 'POST':
                response = requests.post(
                    target_url,
                    json=request.get_json() if request.is_json else None,
                    data=request.form if not request.is_json else None,
                    files=request.files,
                    headers=headers,
                    timeout=30
                )
            elif method == 'PUT':
                response = requests.put(
                    target_url,
                    json=request.get_json() if request.is_json else None,
                    data=request.form if not request.is_json else None,
                    headers=headers,
                    timeout=30
                )
            elif method == 'DELETE':
                response = requests.delete(
                    target_url,
                    headers=headers,
                    timeout=30
                )
            else:
                return jsonify({'error': 'Unsupported method'}), 405
            
            # Return response
            return response.content, response.status_code, dict(response.headers)
            
        finally:
            # Decrement connection count
            service['active_connections'] = max(0, service.get('active_connections', 1) - 1)
    
    def _health_check_loop(self):
        """Background health check loop"""
        while True:
            try:
                self._perform_health_checks()
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                logger.error(f"Health check error: {str(e)}")
                time.sleep(60)  # Wait longer on error
    
    def _perform_health_checks(self):
        """Perform health checks on all registered services"""
        for service_name, services in self.service_registry.services.items():
            for service in services:
                try:
                    health_url = f"{service['url']}{service['health_endpoint']}"
                    response = requests.get(health_url, timeout=10)
                    
                    is_healthy = response.status_code == 200
                    self.service_registry.update_health_status(
                        service_name, service['url'], is_healthy
                    )
                    
                    if is_healthy:
                        # Update health score based on response time
                        response_time = response.elapsed.total_seconds()
                        health_score = max(0.1, 1.0 - (response_time / 5.0))  # 5s max response time
                        service['health_score'] = health_score
                    else:
                        service['health_score'] = 0.0
                        
                except Exception as e:
                    logger.warning(f"Health check failed for {service['url']}: {str(e)}")
                    self.service_registry.update_health_status(
                        service_name, service['url'], False
                    )
                    service['health_score'] = 0.0
    
    def _register_default_routes(self):
        """Register default routes for messaging service"""
        # API routes
        self.register_route('/api/chats', 'messaging', ['GET', 'POST'])
        self.register_route('/api/chats/<int:chat_id>/messages', 'messaging', ['GET'])
        self.register_route('/api/messages/<int:message_id>', 'messaging', ['PUT', 'DELETE'])
        self.register_route('/api/upload', 'messaging', ['POST'])
        self.register_route('/api/search', 'messaging', ['GET'])
        
        # Health check route
        self.register_route('/health', 'messaging', ['GET'])
        
        # WebSocket routes (handled differently)
        self.register_route('/socket.io/', 'messaging', ['GET', 'POST'])

# Middleware functions
def authentication_middleware(request):
    """Authentication middleware"""
    # Skip authentication for health checks
    if request.path == '/health':
        return None
    
    # Check for JWT token
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authentication required'}), 401
    
    # Token validation would be done here
    # For now, we'll assume the token is valid
    return None

def cors_middleware(request):
    """CORS middleware"""
    # Add CORS headers to response
    # This is handled by Flask-CORS, but can be customized here
    return None

def logging_middleware(request):
    """Request logging middleware"""
    start_time = time.time()
    g.start_time = start_time
    
    logger.info(f"Request: {request.method} {request.path} from {request.remote_addr}")
    return None

def security_headers_middleware(request):
    """Security headers middleware"""
    # Add security headers
    # This would typically be done in the response phase
    return None

# Decorator for route registration
def route(path, service_name, methods=['GET'], **kwargs):
    """Decorator for registering routes"""
    def decorator(func):
        # This would be used with the routing system
        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Utility functions
def get_client_ip():
    """Get client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def get_request_id():
    """Get or generate request ID"""
    return request.headers.get('X-Request-ID', f"req_{int(time.time() * 1000)}")

def create_routing_system(app):
    """Factory function to create routing system"""
    routing_system = RoutingSystem(app)
    
    # Add default middleware
    routing_system.add_middleware(authentication_middleware)
    routing_system.add_middleware(cors_middleware)
    routing_system.add_middleware(logging_middleware)
    routing_system.add_middleware(security_headers_middleware)
    
    # Register messaging service instance
    routing_system.service_registry.register_service(
        'messaging',
        app.config.get('HOST', 'localhost'),
        app.config.get('PORT', 5003)
    )
    
    return routing_system
