# use_EPSS
How to use EPSS

Этот скрипт на Python выполняет следующие действия:

1. Получает значение EPSS (Exploit Prediction Scoring System) для заданного CVE (Common Vulnerabilities and Exposures) через API.
2. Читает CSV-файл, содержащий информацию о CVE, их CVSS (Common Vulnerability Scoring System) и количестве (count).
3. Вычисляет комбинированный риск на основе значений CVSS и EPSS для каждого CVE, если CVSS больше 8 и EPSS больше 0.1.
4. Выводит итоговый комбинированный риск в виде числа.
