![Topology](helpers/topology.jpg "Topology")

## Development
- VS Code Remote Development Extension Pack
- Łączymy się z VMką przez SSH za pomocą VS Code
- dzięki temu developujemy z lokalnego kompa, a pliki są na VMce
- ⚠ VS Code nie wspiera już chyba pythona 2.7, więc intellisense będzie robił wzium
- żeby pobrać paczki do pythona trzeba pobrać pip:
  ```
  #jednorazowo

  wget https://bootstrap.pypa.io/pip/2.7/get-pip.py -qO get-pip.py
  python get-pip.py

  #ściąganie paczek:
  python -m pip install <paczka>
  ```
## Uruchomienie
- żeby było łatwiej dodaj alias do ~/.bashrc:
  ``` 
  sudo vi ~/.bashrc 
  ```
  dodaj następujące linijki:

    ```
    alias pox="python /home/student/pox/pox.py"
    export PYTHONPATH=(ścieżka do projektu)
    ```
    dzięki temu zamiast pisać pox `/home/student/pox/pox.py <plik>` piszemy `pox <plik> `
- uruchomienie sieci:
  ```
  python net.py
  ```
- uruchomienie kontrolera:
  ```
  pox controller
  ```
