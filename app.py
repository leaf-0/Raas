"""
Flask Dashboard Application for FME-ABT Detector

Advanced web dashboard with real-time updates, Plotly visualizations,
and comprehensive controls for ransomware detection system.
"""

import os
import json
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any

from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import plotly.graph_objs as go
import plotly.utils

from utils import setup_logger, log_error


class DashboardApp:
    """
    Main dashboard application class
    """
    
    def __init__(self):
        """Initialize the Flask application"""
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'fme-abt-detector-secret-key'

        # Enable CORS for all routes to allow FME Sentinel Watch to connect
        CORS(self.app, origins=["http://localhost:5173", "http://127.0.0.1:5173"])

        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        self.logger = setup_logger(__name__)
        
        # Database paths
        self.events_db = "file_events.db"
        self.alerts_db = "alerts.db"
        
        # Setup routes
        self._setup_routes()
        self._setup_socketio_events()
        
        # Configuration
        self.config = {
            'entropy_threshold': 7.0,
            'variance_threshold': 0.5,
            'chi_square_threshold': 1000,
            'burst_multiplier': 3.0,
            'baseline_days': 7,
            'process_whitelist': [],
            'directory_whitelist': []
        }
        
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def dashboard():
            """Main dashboard page"""
            return render_template('dashboard.html')
        
        @self.app.route('/api/events')
        def get_events():
            """Get recent file events"""
            try:
                hours = request.args.get('hours', 24, type=int)
                limit = request.args.get('limit', 100, type=int)
                
                events = self._get_recent_events(hours, limit)
                return jsonify({
                    'success': True,
                    'data': events,
                    'count': len(events)
                })
                
            except Exception as e:
                log_error(self.logger, e, "Getting events")
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/metrics')
        def get_metrics():
            """Get entropy metrics and statistics"""
            try:
                hours = request.args.get('hours', 24, type=int)
                
                metrics = self._get_entropy_metrics(hours)
                return jsonify({
                    'success': True,
                    'data': metrics
                })
                
            except Exception as e:
                log_error(self.logger, e, "Getting metrics")
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/alerts')
        def get_alerts():
            """Get recent alerts - compatible with both dashboard and FME Sentinel Watch"""
            try:
                hours = request.args.get('hours', 24, type=int)
                severity = request.args.get('severity', None)

                alerts = self._get_recent_alerts(hours, severity)

                # Check if this is a request from FME Sentinel Watch (expects direct array)
                user_agent = request.headers.get('User-Agent', '')
                if 'axios' in user_agent.lower() or request.headers.get('Accept') == 'application/json':
                    # Return direct array for FME Sentinel Watch
                    return jsonify(alerts)
                else:
                    # Return wrapped response for dashboard
                    return jsonify({
                        'success': True,
                        'data': alerts,
                        'count': len(alerts)
                    })

            except Exception as e:
                log_error(self.logger, e, "Getting alerts")
                if 'axios' in request.headers.get('User-Agent', '').lower():
                    return jsonify([])  # Return empty array for FME Sentinel Watch
                else:
                    return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/charts/entropy-trend')
        def entropy_trend_chart():
            """Generate entropy trend chart"""
            try:
                hours = request.args.get('hours', 24, type=int)
                chart_data = self._generate_entropy_trend_chart(hours)
                return jsonify({
                    'success': True,
                    'chart': chart_data
                })
                
            except Exception as e:
                log_error(self.logger, e, "Generating entropy trend chart")
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/charts/burst-heatmap')
        def burst_heatmap_chart():
            """Generate burst activity heatmap"""
            try:
                hours = request.args.get('hours', 24, type=int)
                chart_data = self._generate_burst_heatmap(hours)
                return jsonify({
                    'success': True,
                    'chart': chart_data
                })
                
            except Exception as e:
                log_error(self.logger, e, "Generating burst heatmap")
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/tune', methods=['POST'])
        def tune_thresholds():
            """Update ABT thresholds"""
            try:
                data = request.get_json()
                
                # Update configuration
                if 'entropy_threshold' in data:
                    self.config['entropy_threshold'] = float(data['entropy_threshold'])
                if 'variance_threshold' in data:
                    self.config['variance_threshold'] = float(data['variance_threshold'])
                if 'chi_square_threshold' in data:
                    self.config['chi_square_threshold'] = float(data['chi_square_threshold'])
                if 'burst_multiplier' in data:
                    self.config['burst_multiplier'] = float(data['burst_multiplier'])
                if 'baseline_days' in data:
                    self.config['baseline_days'] = int(data['baseline_days'])
                
                # Apply changes to modules (would need to import and update)
                self._apply_threshold_changes()
                
                return jsonify({
                    'success': True,
                    'message': 'Thresholds updated successfully',
                    'config': self.config
                })
                
            except Exception as e:
                log_error(self.logger, e, "Tuning thresholds")
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/whitelist', methods=['POST'])
        def manage_whitelist():
            """Add/remove processes or directories from whitelist"""
            try:
                data = request.get_json()
                action = data.get('action')  # 'add' or 'remove'
                item_type = data.get('type')  # 'process' or 'directory'
                item_value = data.get('value')
                
                if item_type == 'process':
                    whitelist = self.config['process_whitelist']
                elif item_type == 'directory':
                    whitelist = self.config['directory_whitelist']
                else:
                    return jsonify({'success': False, 'error': 'Invalid type'})
                
                if action == 'add' and item_value not in whitelist:
                    whitelist.append(item_value)
                elif action == 'remove' and item_value in whitelist:
                    whitelist.remove(item_value)
                
                return jsonify({
                    'success': True,
                    'message': f'{item_type.title()} {action}ed successfully',
                    'whitelist': whitelist
                })
                
            except Exception as e:
                log_error(self.logger, e, "Managing whitelist")
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/export')
        def export_dataset():
            """Export dataset as CSV"""
            try:
                dataset_path = self._generate_dataset_csv()
                return send_file(
                    dataset_path,
                    as_attachment=True,
                    download_name=f'fme_abt_dataset_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
                )
                
            except Exception as e:
                log_error(self.logger, e, "Exporting dataset")
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/config')
        def get_config():
            """Get current configuration"""
            return jsonify({
                'success': True,
                'config': self.config
            })

        @self.app.route('/api/status')
        def get_status():
            """Get system status for FME Sentinel Watch"""
            try:
                # Get recent events to determine if monitoring is active
                recent_events = self._get_recent_events(1, 10)  # Last hour
                alerts = self._get_recent_alerts(24)  # Last 24 hours

                # Determine monitoring state based on recent activity
                monitoring_state = 'running' if recent_events else 'stopped'

                status = {
                    'monitoring_state': monitoring_state,
                    'monitored_directories': ['./monitored'],  # Default monitored directory
                    'alerts_count': len(alerts),
                    'last_check': datetime.now().isoformat()
                }

                return jsonify(status)

            except Exception as e:
                log_error(self.logger, e, "Getting system status")
                return jsonify({
                    'monitoring_state': 'stopped',
                    'monitored_directories': [],
                    'alerts_count': 0,
                    'last_check': datetime.now().isoformat()
                })

        @self.app.route('/api/memory')
        def get_memory_usage():
            """Get memory usage information"""
            try:
                import psutil
                memory = psutil.virtual_memory()

                memory_info = {
                    'total': memory.total,
                    'used': memory.used,
                    'percentage': memory.percent
                }

                return jsonify(memory_info)

            except Exception as e:
                log_error(self.logger, e, "Getting memory usage")
                return jsonify({
                    'total': 0,
                    'used': 0,
                    'percentage': 0
                })

        @self.app.route('/api/mitigation', methods=['POST'])
        def toggle_mitigation():
            """Toggle mitigation on/off"""
            try:
                data = request.get_json()
                enabled = data.get('enabled', False)

                # Import alert manager and toggle mitigation
                from alert import get_alert_manager
                alert_manager = get_alert_manager()
                alert_manager.set_mitigation_enabled(enabled)

                return jsonify({
                    'success': True,
                    'message': f'Mitigation {"enabled" if enabled else "disabled"}',
                    'enabled': enabled
                })

            except Exception as e:
                log_error(self.logger, e, "Toggling mitigation")
                return jsonify({'success': False, 'error': str(e)})
    
    def _setup_socketio_events(self):
        """Setup SocketIO events for real-time updates"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection"""
            self.logger.info("Client connected to WebSocket")
            emit('status', {'message': 'Connected to FME-ABT Detector'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            self.logger.info("Client disconnected from WebSocket")
        
        @self.socketio.on('request_update')
        def handle_update_request():
            """Handle request for data update"""
            try:
                # Send latest data
                events = self._get_recent_events(1, 10)  # Last hour, 10 events
                alerts = self._get_recent_alerts(1)      # Last hour
                metrics = self._get_entropy_metrics(1)   # Last hour
                
                emit('data_update', {
                    'events': events,
                    'alerts': alerts,
                    'metrics': metrics,
                    'timestamp': time.time()
                })
                
            except Exception as e:
                log_error(self.logger, e, "Handling update request")
                emit('error', {'message': str(e)})
    
    def _get_recent_events(self, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get recent file events from database"""
        try:
            if not os.path.exists(self.events_db):
                return []
                
            cutoff_time = time.time() - (hours * 3600)
            
            conn = sqlite3.connect(self.events_db)
            try:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM file_events 
                    WHERE timestamp > ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (cutoff_time, limit))
                
                events = []
                for row in cursor.fetchall():
                    event = dict(row)
                    event['formatted_time'] = datetime.fromtimestamp(
                        event['timestamp']
                    ).strftime('%Y-%m-%d %H:%M:%S')
                    events.append(event)
                
                return events
            finally:
                conn.close()
                
        except Exception as e:
            log_error(self.logger, e, "Getting recent events")
            return []
    
    def _get_recent_alerts(self, hours: int = 24, severity: str = None) -> List[Dict]:
        """Get recent alerts from database"""
        try:
            if not os.path.exists(self.alerts_db):
                return []

            cutoff_time = time.time() - (hours * 3600)

            conn = sqlite3.connect(self.alerts_db)
            try:
                conn.row_factory = sqlite3.Row

                query = '''
                    SELECT * FROM alerts
                    WHERE timestamp > ?
                '''
                params = [cutoff_time]

                if severity:
                    query += ' AND severity = ?'
                    params.append(severity)

                query += ' ORDER BY timestamp DESC'

                cursor = conn.execute(query, params)

                alerts = []
                for row in cursor.fetchall():
                    alert = dict(row)
                    # Format timestamp for both dashboard and FME Sentinel Watch
                    alert['formatted_time'] = datetime.fromtimestamp(
                        alert['timestamp']
                    ).strftime('%Y-%m-%d %H:%M:%S')

                    # Ensure timestamp is also in ISO format for FME Sentinel Watch
                    alert['timestamp'] = datetime.fromtimestamp(
                        alert['timestamp']
                    ).isoformat()

                    # Ensure required fields exist with defaults
                    alert['file_path'] = alert.get('file_path', '')
                    alert['process_id'] = alert.get('process_id', 0)
                    alert['process_name'] = alert.get('process_name', '')
                    alert['action_taken'] = alert.get('action_taken', 'none')
                    alert['alert_type'] = alert.get('alert_type', 'unknown')
                    alert['severity'] = alert.get('severity', 'medium')

                    alerts.append(alert)

                return alerts
            finally:
                conn.close()

        except Exception as e:
            log_error(self.logger, e, "Getting recent alerts")
            return []
    
    def _get_entropy_metrics(self, hours: int = 24) -> Dict:
        """Get entropy metrics and statistics"""
        try:
            events = self._get_recent_events(hours, 1000)
            
            # Calculate basic statistics
            total_events = len(events)
            event_types = {}
            processes = {}
            
            for event in events:
                event_type = event.get('event_type', 'unknown')
                process_name = event.get('process_name', 'unknown')
                
                event_types[event_type] = event_types.get(event_type, 0) + 1
                processes[process_name] = processes.get(process_name, 0) + 1
            
            # Get alerts for the same period
            alerts = self._get_recent_alerts(hours)
            alert_counts = {}
            
            for alert in alerts:
                alert_type = alert.get('alert_type', 'unknown')
                alert_counts[alert_type] = alert_counts.get(alert_type, 0) + 1
            
            return {
                'total_events': total_events,
                'event_types': event_types,
                'top_processes': dict(sorted(processes.items(), key=lambda x: x[1], reverse=True)[:10]),
                'alert_counts': alert_counts,
                'total_alerts': len(alerts),
                'period_hours': hours
            }
            
        except Exception as e:
            log_error(self.logger, e, "Getting entropy metrics")
            return {}
    
    def _generate_entropy_trend_chart(self, hours: int = 24) -> Dict:
        """Generate Plotly entropy trend chart"""
        try:
            # This is a simplified version - in practice, you'd calculate actual entropy values
            events = self._get_recent_events(hours, 1000)
            
            # Group events by hour
            hourly_data = {}
            for event in events:
                hour = datetime.fromtimestamp(event['timestamp']).replace(minute=0, second=0, microsecond=0)
                if hour not in hourly_data:
                    hourly_data[hour] = []
                hourly_data[hour].append(event)
            
            # Create chart data
            timestamps = sorted(hourly_data.keys())
            event_counts = [len(hourly_data[ts]) for ts in timestamps]
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=timestamps,
                y=event_counts,
                mode='lines+markers',
                name='File Events',
                line=dict(color='#3B82F6', width=2),
                marker=dict(size=6)
            ))
            
            fig.update_layout(
                title='File Activity Trend',
                xaxis_title='Time',
                yaxis_title='Events per Hour',
                template='plotly_white',
                height=400
            )
            
            return json.loads(plotly.utils.PlotlyJSONEncoder().encode(fig))
            
        except Exception as e:
            log_error(self.logger, e, "Generating entropy trend chart")
            return {}
    
    def _generate_burst_heatmap(self, hours: int = 24) -> Dict:
        """Generate burst activity heatmap"""
        try:
            events = self._get_recent_events(hours, 1000)
            
            # Create heatmap data (simplified)
            heatmap_data = {}
            directories = ['Documents', 'Desktop', 'Downloads', 'Temp', 'Other']
            hours_list = list(range(24))
            
            # Initialize data
            for directory in directories:
                heatmap_data[directory] = [0] * 24
            
            # Populate with event data
            for event in events:
                hour = datetime.fromtimestamp(event['timestamp']).hour
                # Simplified directory categorization
                path = event.get('path', '')
                if 'documents' in path.lower():
                    directory = 'Documents'
                elif 'desktop' in path.lower():
                    directory = 'Desktop'
                elif 'downloads' in path.lower():
                    directory = 'Downloads'
                elif 'temp' in path.lower():
                    directory = 'Temp'
                else:
                    directory = 'Other'
                
                heatmap_data[directory][hour] += 1
            
            # Create heatmap
            z_data = [heatmap_data[directory] for directory in directories]
            
            fig = go.Figure(data=go.Heatmap(
                z=z_data,
                x=hours_list,
                y=directories,
                colorscale='Reds',
                showscale=True
            ))
            
            fig.update_layout(
                title='Burst Activity Heatmap (Events by Directory and Hour)',
                xaxis_title='Hour of Day',
                yaxis_title='Directory',
                template='plotly_white',
                height=400
            )
            
            return json.loads(plotly.utils.PlotlyJSONEncoder().encode(fig))
            
        except Exception as e:
            log_error(self.logger, e, "Generating burst heatmap")
            return {}
    
    def _apply_threshold_changes(self):
        """Apply threshold changes to detection modules"""
        try:
            # In a real implementation, you would import and update the actual modules
            # For now, we'll just log the changes
            self.logger.info(f"Applied threshold changes: {self.config}")
            
        except Exception as e:
            log_error(self.logger, e, "Applying threshold changes")
    
    def _generate_dataset_csv(self) -> str:
        """Generate dataset CSV file"""
        try:
            import csv
            
            dataset_path = "dataset.csv"
            
            # Get all events and alerts
            events = self._get_recent_events(24 * 7, 10000)  # Last week
            alerts = self._get_recent_alerts(24 * 7)
            
            with open(dataset_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'timestamp', 'file_path', 'event_type', 'size', 
                    'process_name', 'alert_type', 'severity', 'outcome'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                # Write events
                for event in events:
                    writer.writerow({
                        'timestamp': event.get('timestamp', ''),
                        'file_path': event.get('path', ''),
                        'event_type': event.get('event_type', ''),
                        'size': event.get('size', ''),
                        'process_name': event.get('process_name', ''),
                        'alert_type': '',
                        'severity': '',
                        'outcome': 'normal'
                    })
                
                # Write alerts
                for alert in alerts:
                    writer.writerow({
                        'timestamp': alert.get('timestamp', ''),
                        'file_path': alert.get('file_path', ''),
                        'event_type': '',
                        'size': '',
                        'process_name': alert.get('process_name', ''),
                        'alert_type': alert.get('alert_type', ''),
                        'severity': alert.get('severity', ''),
                        'outcome': 'suspicious'
                    })
            
            return dataset_path
            
        except Exception as e:
            log_error(self.logger, e, "Generating dataset CSV")
            raise
    
    def run(self, host='127.0.0.1', port=5000, debug=False):
        """Run the Flask application"""
        self.logger.info(f"Starting FME-ABT Dashboard on {host}:{port}")
        self.socketio.run(self.app, host=host, port=port, debug=debug)


# Create global app instance
dashboard_app = DashboardApp()

if __name__ == '__main__':
    dashboard_app.run(debug=True)
