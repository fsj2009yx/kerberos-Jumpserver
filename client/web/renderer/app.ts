type ViewKey = "login" | "terminal" | "logs";

const viewTitle = document.getElementById("viewTitle") as HTMLHeadingElement;
const content = document.getElementById("content") as HTMLElement;
const healthBtn = document.getElementById("healthBtn") as HTMLButtonElement;
const menuItems = Array.from(document.querySelectorAll<HTMLButtonElement>(".menu-item"));

const viewContent: Record<ViewKey, string> = {
  login: "Welcome. This is the login view.",
  terminal: "Terminal to get to Linux.",
  logs: "See the logs and the data",
};

const setActiveView = (view: ViewKey): void => {
  viewTitle.textContent = view.charAt(0).toUpperCase() + view.slice(1);
  content.innerHTML = `<p>${viewContent[view]}</p>`;

  menuItems.forEach((btn) => {
    btn.classList.toggle("is-active", btn.dataset.view === view);
  });
};

menuItems.forEach((item) => {
  item.addEventListener("click", () => {
    const view = item.dataset.view as ViewKey;
    setActiveView(view);
  });
});

healthBtn.addEventListener("click", async () => {
  try {
    const result = await window.systemApi.getHealth();
    content.innerHTML = `<p><strong>API status:</strong> ${result.status}</p><p><strong>Timestamp:</strong> ${result.timestamp}</p>`;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    content.innerHTML = `<p><strong>API call failed:</strong> ${message}</p>`;
  }
});
