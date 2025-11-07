# 網路掃描器 GUI (Network Scanner GUI)

這是一個基於 Python 和 CustomTkinter 開發的圖形化網路掃描器。它可以掃描指定 IP 網段內活躍的主機，並列出其 IP 位址、MAC 位址、主機名稱以及製造商資訊。掃描結果可以匯出為 CSV 檔案。

## 功能特色

*   **IP 網段掃描**：支援 CIDR 格式的 IP 範圍輸入 (例如 `192.168.1.0/24`)。
*   **活躍主機偵測**：透過多執行緒 Ping 掃描快速找出網段內所有活躍的裝置。
*   **詳細資訊收集**：
    *   MAC 位址
    *   主機名稱 (透過反向 DNS 查詢)
    *   裝置製造商 (透過線上 API 查詢)
*   **圖形化使用者介面 (GUI)**：使用 CustomTkinter 提供現代且直觀的操作介面。
*   **結果匯出**：將掃描結果匯出為 CSV 檔案，方便進一步分析。
*   **設定檔管理**：IP 網段、執行緒數量、輸出檔名和 API 金鑰等設定可透過 `config.ini` 檔案輕鬆配置。

## 安裝

1.  **複製儲存庫** (如果您尚未從 GitHub 複製)：
    ```bash
    git clone https://github.com/<您的GitHub使用者名稱>/<您的儲存庫名稱>.git
    cd <您的儲存庫名稱>
    ```

2.  **建立並啟用虛擬環境** (推薦)：
    ```bash
    python -m venv .venv
    # Windows
    .venv\Scripts\activate
    # macOS/Linux
    source .venv/bin/activate
    ```

3.  **安裝所需套件**：
    ```bash
    pip install -r requirements.txt
    ```

## 配置 `config.ini`

在執行程式之前，您需要配置 `config.ini` 檔案。特別是 `API_KEY`，用於查詢裝置製造商資訊。

1.  打開專案根目錄下的 `config.ini` 檔案。
2.  找到 `API_KEY = YOUR_API_KEY_HERE` 這一行。
3.  前往 [macaddress.io](https://macaddress.io/) 網站免費註冊帳號，獲取您自己的 API 金鑰。
4.  將 `YOUR_API_KEY_HERE` 替換為您獲取的真實金鑰。

    ```ini
    [Settings]
    IP_NETWORK = 192.168.1.0/24
    THREAD_COUNT = 50
    OUTPUT_CSV = scan_results.csv
    API_KEY = 您從macaddress.io獲取的金鑰
    ```

    您也可以在此檔案中調整 `IP_NETWORK` (預設掃描網段)、`THREAD_COUNT` (Ping 掃描的執行緒數量) 和 `OUTPUT_CSV` (結果匯出檔名)。

## 使用方式

1.  **啟動程式**：
    ```bash
    python main.py
    ```

2.  **操作介面**：
    *   在 `IP Network (CIDR):` 欄位輸入您要掃描的 IP 網段。
    *   點擊 `Start Scan` 按鈕開始掃描。
    *   掃描進度將顯示在介面底部，結果會即時顯示在文字框中。
    *   掃描完成後，結果將自動匯出到 `config.ini` 中指定的 CSV 檔案。

## 注意事項

*   **API 金鑰**：`macaddress.io` 的免費金鑰有每日查詢限制 (通常為 100 次)。如果超過限制，製造商查詢可能會失敗。
*   **網路連線**：進行製造商查詢需要穩定的網際網路連線。
*   **防火牆**：請確保您的防火牆允許程式進行對外網路連線。

## 貢獻

歡迎任何形式的貢獻，包括錯誤報告、功能建議或程式碼提交。請隨時開啟 Issue 或 Pull Request。

## 授權

此專案採用 MIT 授權條款。詳情請參閱 `LICENSE` 檔案 (如果存在)。
