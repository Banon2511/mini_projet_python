"""
Tests pour l'application Flask
"""
import pytest
import json
from unittest.mock import patch, MagicMock
from pathlib import Path

# Import de l'application Flask
# Note: Ces tests nécessitent que app.py soit mis à jour pour utiliser les nouveaux modules


class TestFlaskApp:
    """Tests pour l'application Flask"""
    
    def test_index_page_loads(self, client):
        """Test que la page d'accueil se charge correctement"""
        response = client.get('/')
        
        assert response.status_code == 200
        assert b'MiniSec Scanner' in response.data
        assert b'formulaire' in response.data.lower() or b'form' in response.data.lower()
    
    def test_api_status_endpoint(self, client):
        """Test l'endpoint de statut API"""
        response = client.get('/api/v1/status')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'yara_available' in data
        assert 'version' in data
        assert 'status' in data
    
    def test_scan_api_missing_folder(self, client):
        """Test l'API de scan avec dossier manquant"""
        response = client.post('/api/v1/scan', 
                             json={},
                             content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['error'] is True
        assert 'folder' in str(data).lower()
    
    def test_scan_api_invalid_folder(self, client):
        """Test l'API de scan avec dossier invalide"""
        response = client.post('/api/v1/scan',
                             json={'folder': '../../../etc/passwd'},
                             content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['error'] is True
    
    def test_scan_api_valid_request(self, client, sample_files_dir):
        """Test l'API de scan avec requête valide"""
        scan_data = {
            'folder': sample_files_dir,
            'recursive': True,
            'analyze_content': False
        }
        
        response = client.post('/api/v1/scan',
                             json=scan_data,
                             content_type='application/json')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert 'results' in data
        assert 'summary' in data
    
    def test_scan_with_content_analysis(self, client, sample_files_dir):
        """Test le scan avec analyse de contenu"""
        scan_data = {
            'folder': sample_files_dir,
            'recursive': False,
            'analyze_content': True
        }
        
        response = client.post('/api/v1/scan',
                             json=scan_data,
                             content_type='application/json')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Vérifier que les résultats contiennent des informations détaillées
        if data['results']:
            result = data['results'][0]
            assert 'reasons' in result
            assert 'score' in result
            assert 'risk_level' in result
    
    def test_recent_scans_endpoint(self, client):
        """Test l'endpoint des scans récents"""
        response = client.get('/api/v1/scans/recent')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)
    
    def test_export_endpoint(self, client):
        """Test l'endpoint d'export"""
        # D'abord créer un scan
        scan_data = {'folder': '/test', 'recursive': False, 'analyze_content': False}
        
        with patch('scanner.SecurityScanner') as mock_scanner:
            mock_instance = MagicMock()
            mock_instance.run_analysis.return_value = (True, "Test completed")
            mock_instance.scan_results = []
            mock_instance.get_scan_summary.return_value = {'total_files': 0}
            mock_scanner.return_value = mock_instance
            
            response = client.post('/api/v1/scan',
                                 json=scan_data,
                                 content_type='application/json')
            
            # Ensuite tester l'export
            export_response = client.get('/api/v1/export?format=json&scan_id=1')
            
            # Le scan_id n'existe pas encore, donc devrait retourner une erreur
            assert export_response.status_code in [400, 404]
    
    @pytest.mark.skip(reason="Rate limiting non activé dans la configuration actuelle")
    def test_rate_limiting(self, client):
        """Test le rate limiting"""
        # Faire plusieurs requêtes rapidement
        responses = []
        for _ in range(15):  # Dépasser la limite par défaut
            response = client.get('/api/v1/status')
            responses.append(response)
        
        # Vérifier qu'au moins une requête est limitée
        limited_responses = [r for r in responses if r.status_code == 429]
        assert len(limited_responses) > 0
    
    def test_error_handling(self, client):
        """Test la gestion d'erreurs"""
        # Test avec une route qui n'existe pas
        response = client.get('/api/v1/nonexistent')
        assert response.status_code == 404
        
        data = json.loads(response.data)
        assert data['error'] is True
        assert 'not_found' in data['error_code'].lower()
    
    def test_cors_headers(self, client):
        """Test les headers CORS"""
        response = client.get('/api/v1/status')
        
        # Vérifier les headers de sécurité
        assert 'X-Content-Type-Options' in response.headers
        assert 'X-Frame-Options' in response.headers
        assert 'X-XSS-Protection' in response.headers


class TestSecurityFeatures:
    """Tests pour les fonctionnalités de sécurité"""
    
    def test_path_traversal_prevention(self, client):
        """Test la prévention du path traversal"""
        malicious_paths = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32',
            '/etc/passwd',
            'C:\\Windows\\System32'
        ]
        
        for path in malicious_paths:
            response = client.post('/api/v1/scan',
                                 json={'folder': path},
                                 content_type='application/json')
            
            assert response.status_code == 400
            data = json.loads(response.data)
            assert data['error'] is True
    
    def test_input_validation(self, client):
        """Test la validation des entrées"""
        # Test avec des types invalides
        invalid_requests = [
            {'folder': 123},  # Nombre au lieu de chaîne
            {'folder': ''},   # Chaîne vide
            {'folder': 'a' * 600},  # Chaîne trop longue
            {'recursive': 'yes'},  # Booléen invalide
            {'analyze_content': 1}   # Booléen invalide
        ]
        
        for invalid_request in invalid_requests:
            response = client.post('/api/v1/scan',
                                 json=invalid_request,
                                 content_type='application/json')
            
            assert response.status_code == 400
            data = json.loads(response.data)
            assert data['error'] is True
    
    def test_sql_injection_prevention(self, client):
        """Test la prévention de l'injection SQL"""
        sql_injection_attempts = [
            "'; DROP TABLE scan_history; --",
            "1' OR '1'='1",
            "'; INSERT INTO scan_history VALUES ('test'); --"
        ]
        
        for attempt in sql_injection_attempts:
            response = client.post('/api/v1/scan',
                                 json={'folder': attempt},
                                 content_type='application/json')
            
            # L'application devrait rejeter ces entrées
            assert response.status_code == 400
    
    def test_xss_prevention(self, client):
        """Test la prévention XSS"""
        xss_attempts = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>"
        ]
        
        for attempt in xss_attempts:
            response = client.post('/api/v1/scan',
                                 json={'folder': attempt},
                                 content_type='application/json')
            
            assert response.status_code == 400


class TestPerformance:
    """Tests de performance"""
    
    def test_scan_performance(self, client, large_files_dir):
        """Test les performances de scan avec de nombreux fichiers"""
        import time
        
        scan_data = {
            'folder': large_files_dir,
            'recursive': False,
            'analyze_content': False
        }
        
        start_time = time.time()
        response = client.post('/api/v1/scan',
                             json=scan_data,
                             content_type='application/json')
        end_time = time.time()
        
        duration = end_time - start_time
        
        assert response.status_code == 200
        # Le scan devrait prendre moins de 10 secondes pour des fichiers de test
        assert duration < 10.0
    
    @pytest.mark.skip(reason="Flask test client non thread-safe avec requêtes concurrentes")
    def test_concurrent_requests(self, client):
        """Test les requêtes concurrentes"""
        import threading
        import time
        
        results = []
        
        def make_request():
            response = client.get('/api/v1/status')
            results.append(response.status_code)
        
        # Créer 10 threads simultanés
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()
        
        # Attendre que tous les threads terminent
        for thread in threads:
            thread.join()
        
        # Vérifier que toutes les requêtes ont réussi
        assert all(status == 200 for status in results)
        assert len(results) == 10
