# Arrête le lab de robustesse SYNTRAF (cible du raccourci « SYNTRAF Lab - arrêt »).
# Les pannes actives sont retirées avant l'arrêt ; les données VictoriaMetrics sont conservées.
$labctl = Join-Path $PSScriptRoot 'labctl.py'
python $labctl down
exit $LASTEXITCODE
