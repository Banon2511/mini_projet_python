# Base de signatures

Ce dossier contient la base de signatures (hashes) pour la détection de menaces connues.

**Contenu actuel :**
- **EICAR** : fichiers test antivirus (2 variantes).
- **Signatures réelles** : hashes MD5/SHA256 issus de threat intelligence publique (APTs, trojans, backdoors), source : [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) (LOKI Custom Evil Hashes). Menaces couvertes : Dark Caracal, Sofacy, Tick Group, SlingShot, Fancy Bear, Ocean Lotus, Patchwork, Lucky Mouse, Orange Worm, Energetic Bear, APT10, Temp.Periscope, etc.

## Fichier `signature_db.json`

Format attendu :

```json
{
  "version": "1.0",
  "signatures": [
    {
      "md5": "44d88612fea8a8f36de82e1278abb02f",
      "sha256": "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd7827",
      "name": "Nom.Menace",
      "type": "Test|Trojan|Ransomware|...",
      "description": "Description optionnelle"
    }
  ]
}
```

- **md5** et **sha256** : au moins un des deux doit être renseigné (en minuscules).
- **name** : nom de la menace affiché dans le rapport.
- **type** : catégorie (informatif).
- **description** : texte optionnel.

Pour ajouter une signature : calculer le hash du fichier (MD5 ou SHA256), ajouter une entrée dans `signatures`, puis relancer un scan. Le scanner recalcule les hashes des fichiers et les compare à cette base.

*Usage pédagogique uniquement. Ne pas inclure de véritables binaires malveillants dans le dépôt.*
