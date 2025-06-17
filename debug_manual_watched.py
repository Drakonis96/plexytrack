#!/usr/bin/env python3
"""
Script de debug para analizar por qué no aparecen elementos marcados manualmente.
"""

import os
import logging
from plex_utils import get_managed_user_plex_history
from app import plex_account

# Configurar logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

def debug_managed_user_history():
    """Debug de historial de usuarios gestionados."""
    
    print("=== DEBUG: Elementos Marcados Manualmente ===")
    
    # Verificar configuración del entorno
    server_name = os.environ.get("PLEX_SERVER_NAME")
    print(f"PLEX_SERVER_NAME: {server_name}")
    
    if not plex_account:
        print("ERROR: No hay cuenta de Plex disponible")
        return
    
    print(f"Cuenta de Plex: {plex_account.username}")
    print(f"Dos factores habilitado: {plex_account.twoFactorEnabled}")
    
    # Listar usuarios gestionados
    print("\n--- Usuarios Gestionados ---")
    try:
        users = plex_account.users()
        managed_users = [u for u in users if hasattr(u, 'home') and u.home]
        
        for user in managed_users:
            print(f"Usuario: {user.username or user.title} (ID: {user.id})")
            
            # Verificar servidores disponibles para este usuario
            try:
                servers = user.servers()
                print(f"  Servidores disponibles: {[s.name for s in servers]}")
                
                if servers:
                    # Probar el primer servidor
                    test_server = servers[0]
                    print(f"  Probando servidor: {test_server.name}")
                    
                    # Obtener historial
                    print(f"  Obteniendo historial para usuario {user.id}...")
                    movies, episodes = get_managed_user_plex_history(plex_account, user.id)
                    print(f"  Resultado: {len(movies)} películas, {len(episodes)} episodios")
                    
                    if len(movies) > 0:
                        print("  Primeras 3 películas:")
                        for i, (guid, data) in enumerate(list(movies.items())[:3]):
                            print(f"    {i+1}. {data['title']} ({data['year']}) - {data['watched_at']}")
                    
                    if len(episodes) > 0:
                        print("  Primeros 3 episodios:")
                        for i, (guid, data) in enumerate(list(episodes.items())[:3]):
                            print(f"    {i+1}. {data['show']} {data['code']} - {data['watched_at']}")
                else:
                    print("  ERROR: No hay servidores disponibles para este usuario")
                    
            except Exception as exc:
                print(f"  ERROR: No se pudieron obtener servidores: {exc}")
                
    except Exception as exc:
        print(f"ERROR: No se pudieron obtener usuarios: {exc}")

if __name__ == "__main__":
    debug_managed_user_history()
