# Ewidencja sprzedaży

Program do ewidencji sprzedaży w działalności nierejestrowanej: kwartalny limit przychodu, uproszczona ewidencja dzienna, rachunki i faktury bez VAT, koszty, kasa fiskalna, DAC7, zestawienie do PIT-36, kopie bezpieczeństwa i hasło z szyfrowaniem.

Program działa w przeglądarce i zapisuje dane wyłącznie na komputerze użytkownika. W tym repozytorium jest tylko kod programu, bez żadnych danych.

## Instalacja

Otwórz adres strony programu (GitHub Pages tego repozytorium) w Chrome lub Edge i kliknij ikonę instalacji na pasku adresu. Po pierwszym uruchomieniu program działa bez internetu, a gdy komputer jest online, sam pobiera nową wersję.

## Budowanie

`src/index.html` to źródło programu. `python3 src/build_offline.py` buduje z niego wersję instalowaną (`src/pwa/`) i plik offline (`src/ewidencja-offline.html`). Każda zmiana na gałęzi `main` publikuje się automatycznie przez GitHub Actions.
