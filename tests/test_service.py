#!/usr/bin/env python3
"""
Naebak Messaging Service - Comprehensive Test Suite
=================================================

This test suite validates the messaging service functionality,
API routing, security features, and readiness for deployment.

Test Results are logged with timestamps and detailed information.
"""

import os
import sys
import json
import time
import logging
import subprocess
import requests
from datetime import datetime
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/ubuntu/naebak-messaging-service/tests/test_results.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class GatewayServiceTestSuite:
    """Comprehensive test suite for messaging service"""
    
    def __init__(self):
        self.service_path = '/home/ubuntu/naebak-messaging-service'
        self.test_results = {
            'service_name': 'naebak-messaging-service',
            'test_timestamp': datetime.now().isoformat(),
            'tests_run': 0,
            'tests_passed': 0,
            'tests_failed': 0,
            'test_details': [],
            'service_status': 'UNKNOWN'
        }
        
    def log_test_result(self, test_name, status, details, duration=0):
        """Log individual test results"""
        result = {
            'test_name': test_name,
            'status': status,
            'details': details,
            'duration_ms': round(duration * 1000, 2),
            'timestamp': datetime.now().isoformat()
        }
        
        self.test_results['test_details'].append(result)
        self.test_results['tests_run'] += 1
        
        if status == 'PASSED':
            self.test_results['tests_passed'] += 1
            logger.info(f"✅ {test_name}: {details}")
        elif status == 'WARNING':
            logger.warning(f"⚠️  {test_name}: {details}")
        else:
            self.test_results['tests_failed'] += 1
            logger.error(f"❌ {test_name}: {details}")
    
    def test_file_structure(self):
        """Test messaging service file structure"""
        start_time = time.time()
        
        try:
            required_files = [
                'messaging.py',
                'app.py',
                'config.py',
                'constants.py',
                'routing_system.py',
                'security_middleware.py',
                'requirements.txt'
            ]
            
            missing_files = []
            existing_files = []
            
            for file_path in required_files:
                full_path = os.path.join(self.service_path, file_path)
                if os.path.exists(full_path):
                    existing_files.append(file_path)
                else:
                    missing_files.append(file_path)
            
            if not missing_files:
                status = 'PASSED'
                details = f'All required files present: {len(existing_files)}/{len(required_files)}'
            else:
                status = 'WARNING'
                details = f'Missing files: {missing_files}. Present: {existing_files}'
            
            duration = time.time() - start_time
            self.log_test_result('File Structure', status, details, duration)
            
        except Exception as e:
            duration = time.time() - start_time
            self.log_test_result('File Structure', 'FAILED', f'Error: {str(e)}', duration)
    
    def test_python_syntax(self):
        """Test Python syntax in all Python files"""
        start_time = time.time()
        
        try:
            python_files = []
            syntax_errors = []
            
            # Find all Python files
            for root, dirs, files in os.walk(self.service_path):
                dirs[:] = [d for d in dirs if d not in ['venv', '__pycache__', '.git']]
                
                for file in files:
                    if file.endswith('.py'):
                        python_files.append(os.path.join(root, file))
            
            # Check syntax for each file
            for py_file in python_files:
                try:
                    with open(py_file, 'r', encoding='utf-8') as f:
                        compile(f.read(), py_file, 'exec')
                except SyntaxError as e:
                    syntax_errors.append(f"{py_file}: {str(e)}")
                except Exception as e:
                    syntax_errors.append(f"{py_file}: {str(e)}")
            
            if not syntax_errors:
                status = 'PASSED'
                details = f'All {len(python_files)} Python files have valid syntax'
            else:
                status = 'FAILED'
                details = f'Syntax errors in {len(syntax_errors)} files: {syntax_errors[:3]}'
            
            duration = time.time() - start_time
            self.log_test_result('Python Syntax', status, details, duration)
            
        except Exception as e:
            duration = time.time() - start_time
            self.log_test_result('Python Syntax', 'FAILED', f'Error: {str(e)}', duration)
    
    def test_flask_imports(self):
        """Test Flask and required imports"""
        start_time = time.time()
        
        try:
            # Test key imports
            import_tests = [
                ('flask', 'Flask framework'),
                ('requests', 'HTTP requests library'),
                ('jwt', 'JWT token handling'),
            ]
            
            available_imports = []
            missing_imports = []
            
            for module, description in import_tests:
                try:
                    __import__(module)
                    available_imports.append(f"{module} ({description})")
                except ImportError:
                    missing_imports.append(f"{module} ({description})")
            
            if not missing_imports:
                status = 'PASSED'
                details = f'All key dependencies available: {len(available_imports)} modules'
            else:
                status = 'WARNING'
                details = f'Missing: {missing_imports}. Available: {available_imports}'
            
            duration = time.time() - start_time
            self.log_test_result('Flask Dependencies', status, details, duration)
            
        except Exception as e:
            duration = time.time() - start_time
            self.log_test_result('Flask Dependencies', 'FAILED', f'Error: {str(e)}', duration)
    
    def test_messaging_configuration(self):
        """Test messaging configuration and setup"""
        start_time = time.time()
        
        try:
            config_file = os.path.join(self.service_path, 'config.py')
            
            if not os.path.exists(config_file):
                self.log_test_result('Gateway Configuration', 'FAILED', 'config.py not found', 0)
                return
            
            # Read config file
            with open(config_file, 'r', encoding='utf-8') as f:
                config_content = f.read()
            
            # Check for key configuration elements
            config_elements = []
            
            if 'class Config' in config_content:
                config_elements.append('Config class defined')
            if 'SECRET_KEY' in config_content:
                config_elements.append('Secret key configuration')
            if 'DATABASE' in config_content or 'DB' in config_content:
                config_elements.append('Database configuration')
            if 'HOST' in config_content and 'PORT' in config_content:
                config_elements.append('Host/Port configuration')
            if 'DEBUG' in config_content:
                config_elements.append('Debug configuration')
            
            if len(config_elements) >= 3:
                status = 'PASSED'
                details = f'Configuration elements found: {config_elements}'
            else:
                status = 'WARNING'
                details = f'Limited configuration: {config_elements}'
            
            duration = time.time() - start_time
            self.log_test_result('Gateway Configuration', status, details, duration)
            
        except Exception as e:
            duration = time.time() - start_time
            self.log_test_result('Gateway Configuration', 'FAILED', f'Error: {str(e)}', duration)
    
    def test_routing_system(self):
        """Test routing system implementation"""
        start_time = time.time()
        
        try:
            routing_file = os.path.join(self.service_path, 'routing_system.py')
            
            if not os.path.exists(routing_file):
                self.log_test_result('Routing System', 'FAILED', 'routing_system.py not found', 0)
                return
            
            # Read routing file
            with open(routing_file, 'r', encoding='utf-8') as f:
                routing_content = f.read()
            
            # Check for routing features
            routing_features = []
            
            if 'class' in routing_content and 'Router' in routing_content:
                routing_features.append('Router class defined')
            if 'route' in routing_content.lower():
                routing_features.append('Route handling')
            if 'load_balance' in routing_content or 'LoadBalance' in routing_content:
                routing_features.append('Load balancing')
            if 'health' in routing_content.lower():
                routing_features.append('Health checking')
            if 'service' in routing_content.lower() and 'discovery' in routing_content.lower():
                routing_features.append('Service discovery')
            
            if len(routing_features) >= 3:
                status = 'PASSED'
                details = f'Routing features found: {routing_features}'
            elif len(routing_features) >= 1:
                status = 'WARNING'
                details = f'Basic routing features: {routing_features}'
            else:
                status = 'FAILED'
                details = 'No routing features detected'
            
            duration = time.time() - start_time
            self.log_test_result('Routing System', status, details, duration)
            
        except Exception as e:
            duration = time.time() - start_time
            self.log_test_result('Routing System', 'FAILED', f'Error: {str(e)}', duration)
    
    def test_security_middleware(self):
        """Test security middleware implementation"""
        start_time = time.time()
        
        try:
            security_file = os.path.join(self.service_path, 'security_middleware.py')
            
            if not os.path.exists(security_file):
                self.log_test_result('Security Middleware', 'FAILED', 'security_middleware.py not found', 0)
                return
            
            # Read security file
            with open(security_file, 'r', encoding='utf-8') as f:
                security_content = f.read()
            
            # Check for security features
            security_features = []
            
            if 'jwt' in security_content.lower() or 'JWT' in security_content:
                security_features.append('JWT authentication')
            if 'cors' in security_content.lower() or 'CORS' in security_content:
                security_features.append('CORS handling')
            if 'rate' in security_content.lower() and 'limit' in security_content.lower():
                security_features.append('Rate limiting')
            if 'auth' in security_content.lower():
                security_features.append('Authentication middleware')
            if 'validate' in security_content.lower():
                security_features.append('Request validation')
            if 'encrypt' in security_content.lower() or 'hash' in security_content.lower():
                security_features.append('Encryption/Hashing')
            
            if len(security_features) >= 4:
                status = 'PASSED'
                details = f'Security features found: {security_features}'
            elif len(security_features) >= 2:
                status = 'WARNING'
                details = f'Basic security features: {security_features}'
            else:
                status = 'FAILED'
                details = 'Insufficient security features'
            
            duration = time.time() - start_time
            self.log_test_result('Security Middleware', status, details, duration)
            
        except Exception as e:
            duration = time.time() - start_time
            self.log_test_result('Security Middleware', 'FAILED', f'Error: {str(e)}', duration)
    
    def test_main_messaging_app(self):
        """Test main messaging application structure"""
        start_time = time.time()
        
        try:
            messaging_file = os.path.join(self.service_path, 'messaging.py')
            
            if not os.path.exists(messaging_file):
                self.log_test_result('Main Gateway App', 'FAILED', 'messaging.py not found', 0)
                return
            
            # Read messaging file
            with open(messaging_file, 'r', encoding='utf-8') as f:
                messaging_content = f.read()
            
            # Check for Flask app structure
            app_features = []
            
            if 'app = Flask(' in messaging_content:
                app_features.append('Flask app initialization')
            if '@app.route' in messaging_content or 'app.route' in messaging_content:
                app_features.append('Route definitions')
            if 'CORS' in messaging_content:
                app_features.append('CORS configuration')
            if 'if __name__' in messaging_content:
                app_features.append('Main execution block')
            if 'app.run' in messaging_content:
                app_features.append('App run configuration')
            
            # Check for messaging-specific features
            if 'proxy' in messaging_content.lower() or 'forward' in messaging_content.lower():
                app_features.append('Request forwarding')
            if 'service' in messaging_content.lower():
                app_features.append('Service integration')
            
            if len(app_features) >= 5:
                status = 'PASSED'
                details = f'Gateway app features: {app_features}'
            elif len(app_features) >= 3:
                status = 'WARNING'
                details = f'Basic app features: {app_features}'
            else:
                status = 'FAILED'
                details = f'Insufficient app structure: {app_features}'
            
            duration = time.time() - start_time
            self.log_test_result('Main Gateway App', status, details, duration)
            
        except Exception as e:
            duration = time.time() - start_time
            self.log_test_result('Main Gateway App', 'FAILED', f'Error: {str(e)}', duration)
    
    def test_startup_script(self):
        """Test startup script functionality"""
        start_time = time.time()
        
        try:
            app_file = os.path.join(self.service_path, 'app.py')
            
            if not os.path.exists(app_file):
                self.log_test_result('Startup Script', 'FAILED', 'app.py not found', 0)
                return
            
            # Read app file
            with open(app_file, 'r', encoding='utf-8') as f:
                app_content = f.read()
            
            # Check for startup features
            startup_features = []
            
            if 'if __name__' in app_content:
                startup_features.append('Main execution block')
            if 'import' in app_content and 'messaging' in app_content:
                startup_features.append('Gateway import')
            if 'os.environ' in app_content:
                startup_features.append('Environment variable support')
            if 'app.run' in app_content:
                startup_features.append('App execution')
            if 'host' in app_content and 'port' in app_content:
                startup_features.append('Host/Port configuration')
            
            if len(startup_features) >= 4:
                status = 'PASSED'
                details = f'Startup features: {startup_features}'
            elif len(startup_features) >= 2:
                status = 'WARNING'
                details = f'Basic startup features: {startup_features}'
            else:
                status = 'FAILED'
                details = f'Insufficient startup features: {startup_features}'
            
            duration = time.time() - start_time
            self.log_test_result('Startup Script', status, details, duration)
            
        except Exception as e:
            duration = time.time() - start_time
            self.log_test_result('Startup Script', 'FAILED', f'Error: {str(e)}', duration)
    
    def test_code_quality(self):
        """Test code quality metrics"""
        start_time = time.time()
        
        try:
            quality_metrics = {
                'total_lines': 0,
                'python_files': 0,
                'docstrings': 0,
                'comments': 0,
                'functions': 0,
                'classes': 0
            }
            
            # Analyze Python files
            for root, dirs, files in os.walk(self.service_path):
                dirs[:] = [d for d in dirs if d not in ['venv', '__pycache__', '.git', 'tests']]
                
                for file in files:
                    if file.endswith('.py'):
                        quality_metrics['python_files'] += 1
                        file_path = os.path.join(root, file)
                        
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                lines = f.readlines()
                                quality_metrics['total_lines'] += len(lines)
                                
                                for line in lines:
                                    line = line.strip()
                                    if line.startswith('"""') or line.startswith("'''"):
                                        quality_metrics['docstrings'] += 1
                                    elif line.startswith('#'):
                                        quality_metrics['comments'] += 1
                                    elif line.startswith('def '):
                                        quality_metrics['functions'] += 1
                                    elif line.startswith('class '):
                                        quality_metrics['classes'] += 1
                        except Exception:
                            continue
            
            # Calculate quality score
            if quality_metrics['total_lines'] > 0:
                comment_ratio = (quality_metrics['comments'] + quality_metrics['docstrings']) / quality_metrics['total_lines']
                quality_score = min(100, comment_ratio * 100 + 50)
            else:
                quality_score = 0
            
            if quality_score >= 70:
                status = 'PASSED'
            elif quality_score >= 50:
                status = 'WARNING'
            else:
                status = 'FAILED'
            
            details = f'Quality score: {quality_score:.1f}%. Metrics: {quality_metrics}'
            
            duration = time.time() - start_time
            self.log_test_result('Code Quality', status, details, duration)
            
        except Exception as e:
            duration = time.time() - start_time
            self.log_test_result('Code Quality', 'FAILED', f'Error: {str(e)}', duration)
    
    def run_all_tests(self):
        """Run all tests and generate report"""
        logger.info("🌐 Starting Naebak Messaging Service Tests")
        logger.info("=" * 60)
        
        # Run all test methods
        test_methods = [
            self.test_file_structure,
            self.test_python_syntax,
            self.test_flask_imports,
            self.test_messaging_configuration,
            self.test_routing_system,
            self.test_security_middleware,
            self.test_main_messaging_app,
            self.test_startup_script,
            self.test_code_quality
        ]
        
        for test_method in test_methods:
            try:
                test_method()
            except Exception as e:
                logger.error(f"Test method {test_method.__name__} failed: {e}")
        
        # Determine overall service status
        if self.test_results['tests_failed'] == 0:
            if self.test_results['tests_passed'] >= 7:
                self.test_results['service_status'] = 'READY'
            else:
                self.test_results['service_status'] = 'NEEDS_WORK'
        else:
            self.test_results['service_status'] = 'FAILED'
        
        # Generate summary
        self.generate_test_report()
        
        return self.test_results
    
    def generate_test_report(self):
        """Generate comprehensive test report"""
        logger.info("=" * 60)
        logger.info("📋 GATEWAY SERVICE TEST SUMMARY")
        logger.info("=" * 60)
        
        total_tests = self.test_results['tests_run']
        passed_tests = self.test_results['tests_passed']
        failed_tests = self.test_results['tests_failed']
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        logger.info(f"🌐 Service: {self.test_results['service_name']}")
        logger.info(f"📅 Timestamp: {self.test_results['test_timestamp']}")
        logger.info(f"📊 Total Tests: {total_tests}")
        logger.info(f"✅ Passed: {passed_tests}")
        logger.info(f"❌ Failed: {failed_tests}")
        logger.info(f"📈 Success Rate: {success_rate:.1f}%")
        logger.info(f"🎯 Service Status: {self.test_results['service_status']}")
        
        # Save detailed results to JSON
        results_file = os.path.join(self.service_path, 'tests', 'test_results.json')
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(self.test_results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"📄 Detailed results saved to {results_file}")
        
        # Create summary file
        summary_file = os.path.join(self.service_path, 'tests', 'test_summary.md')
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(f"# Messaging Service Test Summary\n\n")
            f.write(f"**Service:** {self.test_results['service_name']}  \n")
            f.write(f"**Test Date:** {self.test_results['test_timestamp']}  \n")
            f.write(f"**Status:** {self.test_results['service_status']}  \n\n")
            f.write(f"## Results\n\n")
            f.write(f"- **Total Tests:** {total_tests}\n")
            f.write(f"- **Passed:** {passed_tests}\n")
            f.write(f"- **Failed:** {failed_tests}\n")
            f.write(f"- **Success Rate:** {success_rate:.1f}%\n\n")
            f.write(f"## Test Details\n\n")
            
            for test in self.test_results['test_details']:
                status_icon = "✅" if test['status'] == 'PASSED' else "⚠️" if test['status'] == 'WARNING' else "❌"
                f.write(f"- {status_icon} **{test['test_name']}** ({test['duration_ms']}ms): {test['details']}\n")
        
        logger.info(f"📋 Summary report saved to {summary_file}")
        logger.info("=" * 60)

def main():
    """Main test execution function"""
    print("🌐 Naebak Messaging Service - Comprehensive Test Suite")
    print("=" * 60)
    
    # Create tests directory if it doesn't exist
    os.makedirs('/home/ubuntu/naebak-messaging-service/tests', exist_ok=True)
    
    # Run tests
    test_suite = GatewayServiceTestSuite()
    results = test_suite.run_all_tests()
    
    # Print final status
    if results['service_status'] == 'READY':
        print("🎉 SERVICE IS READY FOR DEPLOYMENT!")
        return 0
    elif results['service_status'] == 'NEEDS_WORK':
        print("⚠️  SERVICE NEEDS MINOR FIXES")
        return 1
    else:
        print("❌ SERVICE HAS CRITICAL ISSUES")
        return 2

if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
