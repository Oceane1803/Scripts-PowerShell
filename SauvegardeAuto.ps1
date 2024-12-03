param(
    [string]$sourceFolder = "$env:SystemDrive\Donnees", # Chemin vers le dossier source
    [string]$backupFolder = "\\192.168.1.202\Sauvegardes", # Chemin vers le dossier de sauvegarde
    [string]$logFile = "C:\Logs\backup_log.txt", # Chemin vers le fichier de log
    [string]$errorLogFile = "C:\Logs\backup_error_log.txt", # Chemin vers le fichier de log des erreurs
    [int]$daysThreshold = 700 # Seuil en jours
)

# Créer le dossier de logs s'il n'existe pas
$logPath = Split-Path -Parent $logFile
if (-not (Test-Path $logPath)) {
    New-Item -ItemType Directory -Path $logPath -Force
}

# Fichier de log pour cette exécution
$timestamp = Get-Date -Format "yyyy-MM-dd-HH-mm"
$executionLogFile = "C:\Logs\backup_log_$timestamp.txt"
$executionErrorLogFile = "C:\Logs\backup_error_log_$timestamp.txt"

# Fonction de log
function Write-Log {
    param($Message, [switch]$IsError)
    $logMessage = "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss'): $Message"
    Add-Content -Path $executionLogFile -Value $logMessage
    Write-Host $logMessage
    if ($IsError) {
        Add-Content -Path $executionErrorLogFile -Value $logMessage
    }
}

# Fonction pour obtenir les permissions d'un chemin
function Get-PathPermissions {
    param ([string]$Path)
    $permissions = @{}
    try {
        $acl = Get-Acl -Path $Path
        if ($null -ne $acl) {
            foreach ($access in $acl.Access) {
                $identity = $access.IdentityReference.Value
                if (!$permissions.ContainsKey($identity)) {
                    $permissions[$identity] = $access.FileSystemRights
                } else {
                    $permissions[$identity] = $permissions[$identity] -bor $access.FileSystemRights
                }
            }
        }
        return $permissions
    } catch {
        Write-Log "Erreur lors de la récupération des permissions pour $Path : $_" -IsError
        throw
    }
}

# Fonction pour vérifier si un utilisateur est administrateur
function Is-Admin {
    param ([string]$Identity)
    return $Identity -match "Administrateurs|Administrateur|Administrators|Système|Domain Admins"
}

# Fonction pour appliquer les permissions sur un dossier
function Set-FolderPermissions {
    param ([string]$Path, [hashtable]$Permissions)
    try {
        $acl = Get-Acl -Path $Path
        if ($null -ne $acl) {
            $acl.SetAccessRuleProtection($true, $false)
            $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
            foreach ($identity in $Permissions.Keys) {
                $rights = $Permissions[$identity]
                if (-not (Is-Admin -Identity $identity)) {
                    $rights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                }
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $identity,
                    $rights,
                    "ContainerInherit,ObjectInherit",
                    "None",
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
                $acl.AddAccessRule($rule)
            }
            Set-Acl -Path $Path -AclObject $acl
            Write-Log "Permissions appliquées sur le dossier : $Path"
        }
    } catch {
        Write-Log "Erreur lors de l'application des permissions sur le dossier : $_" -IsError
        throw
    }
}

# Fonction pour appliquer les permissions sur un fichier
function Set-FilePermissions {
    param ([string]$Path, [hashtable]$Permissions)
    try {
        $acl = Get-Acl -Path $Path
        if ($null -ne $acl) {
            $acl.SetAccessRuleProtection($true, $false)
            $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
            foreach ($identity in $Permissions.Keys) {
                $rights = $Permissions[$identity]
                if (-not (Is-Admin -Identity $identity)) {
                    $rights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                }
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $identity,
                    $rights,
                    "None",
                    "None",
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
                $acl.AddAccessRule($rule)
            }
            Set-Acl -Path $Path -AclObject $acl
            try {
                Set-ItemProperty -Path $Path -Name IsReadOnly -Value $true
                Write-Log "Propriété IsReadOnly appliquée : $Path"
            } catch {
                Write-Log "Erreur lors de la modification de la propriété IsReadOnly pour le fichier : $Path - $_" -IsError
            }
            Write-Log "Permissions appliquées sur le fichier : $Path"
        }
    } catch {
        Write-Log "Erreur lors de l'application des permissions sur le fichier : $_" -IsError
        throw
    }
}

# Fonction pour fusionner les permissions de deux hashtables
function Merge-Permissions {
    param ([hashtable]$Permissions1, [hashtable]$Permissions2)
    $mergedPermissions = @{}
    $allIdentities = @($Permissions1.Keys) + @($Permissions2.Keys) | Select-Object -Unique
    foreach ($identity in $allIdentities) {
        if ($Permissions1.ContainsKey($identity) -and $Permissions2.ContainsKey($identity)) {
            $mergedPermissions[$identity] = $Permissions1[$identity] -bor $Permissions2[$identity]
        } elseif ($Permissions1.ContainsKey($identity)) {
            $mergedPermissions[$identity] = $Permissions1[$identity]
        } else {
            $mergedPermissions[$identity] = $Permissions2[$identity]
        }
    }
    return $mergedPermissions
}

# Fonction pour la sauvegarde des fichiers
function Start-FileBackUp {
    Write-Log "Début du processus de sauvegarde"

    # Vérification du dossier source
    if (-not (Test-Path $sourceFolder)) {
        Write-Log "Erreur: Dossier source inaccessible ou inexistant: $sourceFolder" -IsError
        return
    }
    Write-Log "Dossier source trouvé: $sourceFolder"

    #Vérification/création du dossier de sauvegarde
    if (-not (Test-Path $backupFolder)) {
        try {
            New-Item -ItemType Directory -Path $backupFolder -Force | Out-Null
            Write-Log "Dossier de sauvegarde créé : $backupFolder"
        } catch {
            Write-Log "Erreur lors de la création du dossier de sauvegarde: $backupFolder - $_" -IsError
            return
        }
    }
    try {
        # Récupération de TOUS les fichiers dans le dossier source
        $filesToMove = Get-ChildItem -Path $sourceFolder -Recurse -File -Force |
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$daysThreshold) }

        $totalFiles = $filesToMove.Count
        Write-Log "Nombre total de fichiers à traiter : $totalFiles"

        $processedFiles = 0
        foreach ($file in $filesToMove) {
            $processedFiles++
            Write-Log "[$processedFiles/$totalFiles] Traitement du fichier: $($file.FullName)"

            # Calcul du chemin relatif pour préserver la structure
            $relativePath = $file.FullName.Substring($sourceFolder.Length)
            $destinationPath = Join-Path $backupFolder $relativePath
            $destinationDir = Split-Path -Parent $destinationPath

            try {
                $sourcePermissions = Get-PathPermissions -Path $file.FullName
                if ($null -ne $sourcePermissions) {
                    if (-not (Test-Path $destinationDir)) {
                        New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
                        Write-Log "Dossier de destination créé: $destinationDir"
                    }

                    $existingPermissions = @{}
                    if (Test-Path $destinationPath) {
                        $existingPermissions = Get-PathPermissions -Path $destinationPath
                    }

                    $mergedPermissions = Merge-Permissions -Permissions1 $sourcePermissions -Permissions2 $existingPermissions

                    # Application des permissions sur le dossier de destination
                    Set-FolderPermissions -Path $destinationDir -Permissions $mergedPermissions

                    # Copie du fichier
                    Copy-Item -Path $file.FullName -Destination $destinationPath -Force
                    Write-Log "Fichier copié: $destinationPath"

                    # Application des permissions sur le fichier
                    Set-FilePermissions -Path $destinationPath -Permissions $mergedPermissions

                } else {
                    Write-Log "Aucune permission trouvée pour le fichier: $($file.FullName)" -IsError
                }
            } catch {
                Write-Log "Erreur lors du traitement du fichier: $_" -IsError
            }
        }

        Write-Log "Traitement terminé. $processedFiles fichiers traités sur $totalFiles"
    } catch {
        Write-Log "Erreur lors du processus de sauvegarde: $_" -IsError
    }
}

# Exécution du script
Write-Log "=== Démarrage du script ==="
Write-Log "Version PowerShell: $($PSVersionTable.PSVersion)"
Write-Log "Utilisateur actuel: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Log "Dossier source configuré: $sourceFolder"
Write-Log "Dossier de sauvegarde configuré: $backupFolder"
Write-Log "Seuil de sauvegarde: $daysThreshold jours"
Start-FileBackUp
Write-Log "=== Fin du script ==="
