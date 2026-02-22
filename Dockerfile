# MiniSec Scanner - Docker Image
FROM python:3.11-slim

# Définir le répertoire de travail
WORKDIR /app

# Variables d'environnement
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    FLASK_APP=wsgi.py

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libyara-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copier les fichiers de dépendances
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code de l'application
COPY . .

# Créer les répertoires nécessaires
RUN mkdir -p logs uploads quarantine reports static

# Créer un utilisateur non-root
RUN useradd --create-home --shell /bin/bash minisec && \
    chown -R minisec:minisec /app

# Changer vers l'utilisateur non-root
USER minisec

# Exposer le port
EXPOSE 5000

# Commande de démarrage
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "300", "wsgi:app"]

# Labels pour Docker
LABEL maintainer="MiniSec Scanner Team" \
      version="2.0" \
      description="MiniSec Scanner - Outil de sécurité de fichiers" \
      org.opencontainers.image.source="https://github.com/your-repo/minisec-scanner"
