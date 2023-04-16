![Topology](helpers/topology.jpg "Topology")

## Development
- VS Code Remote Development Extension Pack
- Łączymy się z VMką przez SSH za pomocą VS Code
- dzięki temu developujemy z lokalnego kompa, a pliki są na VMce

## Uruchomienie
żeby było łatwiej dodaj alias do ~/.bashrc:
- ``` 
  sudo vi ~/.bashrc 
  ```
  dodaj następującą linijkę:

    ```
    alias pox="py /home/student/pox/pox.py"
- dodaj ścieżkę z projektem  do PYTHONPATH, dzięki czemu pox wykryje plik z kontrolerem:
  ``` 
  cd eines_project_1
  export PYTHONPATH=$PYTHONPATH:$(pwd) 
  ```
- uruchomienie sieci:
  ```
  python net.py
  ```
- uruchomienie kontrolera:
  ```
  pox controller
  ```
