
document.getElementById("collect").addEventListener("click", async () => {
  const startValue = document.getElementById("startDate").value;
  const endValue = document.getElementById("endDate").value;
  const status = document.getElementById("status");

  if (!startValue || !endValue) {
    status.textContent = "Please select both dates.";
    return;
  }

  const start = new Date(startValue + "T00:00:00").getTime();
  const end = new Date(endValue + "T23:59:59.999").getTime();

  if (Number.isNaN(start) || Number.isNaN(end) || start > end) {
    status.textContent = "Please select a valid date range.";
    return;
  }

  status.textContent = "Collecting browser history...";

  try {
    const items = await chrome.history.search({
      text: "",
      startTime: start,
      endTime: end,
      maxResults: 10000
    });

    const records = items
      .filter(item =>
        item.url &&
        (item.url.startsWith("http://") ||
         item.url.startsWith("https://"))
      )
      .map(item => ({
        url: item.url,
        title: item.title || "",
        lastVisitTime: item.lastVisitTime != null
          ? Math.trunc(item.lastVisitTime)
          : null,
        visitCount: item.visitCount || 0
      }));

    status.textContent = `Sending ${records.length} records...`;

    const investigationId =
      crypto.randomUUID
        ? crypto.randomUUID()
        : "investigation-" + Date.now();

    const response = await fetch(
      "https://df-project.onrender.com/api/history",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer BrowserForensics_7Kp9M2vQ4xL8"
        },
        body: JSON.stringify({
          investigation_id: investigationId,
          start_date: startValue,
          end_date: endValue,
          records: records
        })
      }
    );

    const result = await response.json().catch(() => ({}));

    if (!response.ok) {
      const detail = result.detail;
      throw new Error(
        typeof detail === "string"
          ? detail
          : JSON.stringify(detail || result) ||
            `HTTP error ${response.status}`
      );
    }

    status.textContent =
      `Success! Sent ${result.received_records} records.`;

    console.log("Investigation ID:", result.investigation_id);
    console.log("Backend response:", result);

  } catch (error) {
    console.error("History submission failed:", error);
    status.textContent = "Error: " + error.message;
  }
});
