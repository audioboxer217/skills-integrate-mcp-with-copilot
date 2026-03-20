document.addEventListener("DOMContentLoaded", () => {
  const AUTH_TOKEN_KEY = "authToken";

  const activitiesList = document.getElementById("activities-list");
  const activitySelect = document.getElementById("activity");
  const signupForm = document.getElementById("signup-form");
  const messageDiv = document.getElementById("message");
  const authForm = document.getElementById("auth-form");
  const authNameGroup = document.getElementById("auth-name-group");
  const authNameInput = document.getElementById("auth-name");
  const authEmailInput = document.getElementById("auth-email");
  const authPasswordInput = document.getElementById("auth-password");
  const authSubmitBtn = document.getElementById("auth-submit-btn");
  const showLoginBtn = document.getElementById("show-login");
  const showSignupBtn = document.getElementById("show-signup");
  const authContainer = document.getElementById("auth-container");
  const authRequiredNote = document.getElementById("auth-required-note");
  const signupContainer = document.getElementById("signup-container");
  const userStatus = document.getElementById("user-status");
  const userWelcome = document.getElementById("user-welcome");
  const logoutBtn = document.getElementById("logout-btn");
  const currentUserEmailInput = document.getElementById("current-user-email");

  let authMode = "login";
  let currentUser = null;

  function getToken() {
    return localStorage.getItem(AUTH_TOKEN_KEY);
  }

  function setToken(token) {
    localStorage.setItem(AUTH_TOKEN_KEY, token);
  }

  function clearToken() {
    localStorage.removeItem(AUTH_TOKEN_KEY);
  }

  function setAuthMode(mode) {
    authMode = mode;
    authNameGroup.classList.toggle("hidden", mode !== "signup");
    authNameInput.required = mode === "signup";
    authSubmitBtn.textContent = mode === "signup" ? "Sign Up" : "Login";
  }

  function updateAuthUI() {
    const isAuthenticated = Boolean(currentUser);
    authContainer.classList.toggle("hidden", isAuthenticated);
    signupContainer.classList.toggle("hidden", !isAuthenticated);
    userStatus.classList.toggle("hidden", !isAuthenticated);
    authRequiredNote.classList.toggle("hidden", isAuthenticated);

    if (isAuthenticated) {
      userWelcome.textContent = `Welcome, ${currentUser.name} (${currentUser.role})`;
      currentUserEmailInput.value = currentUser.email;
    } else {
      userWelcome.textContent = "";
      currentUserEmailInput.value = "";
    }
  }

  function showMessage(text, type = "info") {
    messageDiv.textContent = text;
    messageDiv.className = type;
    messageDiv.classList.remove("hidden");

    setTimeout(() => {
      messageDiv.classList.add("hidden");
    }, 5000);
  }

  function handleUnauthorized() {
    currentUser = null;
    clearToken();
    updateAuthUI();
    authRequiredNote.classList.remove("hidden");
    authContainer.scrollIntoView({ behavior: "smooth", block: "start" });
    showMessage("Your session expired. Please log in again.", "error");
  }

  // Function to fetch activities from API
  async function fetchActivities() {
    try {
      const response = await fetch("/activities");
      const activities = await response.json();

      // Clear loading message
      activitiesList.innerHTML = "";
      activitySelect.innerHTML =
        '<option value="">-- Select an activity --</option>';

      // Populate activities list
      Object.entries(activities).forEach(([name, details]) => {
        const activityCard = document.createElement("div");
        activityCard.className = "activity-card";

        const spotsLeft =
          details.max_participants - details.participants.length;

        // Create participants HTML with delete icons instead of bullet points
        const participantsHTML =
          details.participants.length > 0
            ? `<div class="participants-section">
              <h5>Participants:</h5>
              <ul class="participants-list">
                ${details.participants
                  .map(
                    (email) =>
                      `<li><span class="participant-email">${email}</span>${
                        currentUser && email === currentUser.email
                          ? `<button class="delete-btn" data-activity="${name}">❌</button>`
                          : ""
                      }</li>`
                  )
                  .join("")}
              </ul>
            </div>`
            : `<p><em>No participants yet</em></p>`;

        activityCard.innerHTML = `
          <h4>${name}</h4>
          <p>${details.description}</p>
          <p><strong>Schedule:</strong> ${details.schedule}</p>
          <p><strong>Availability:</strong> ${spotsLeft} spots left</p>
          <div class="participants-container">
            ${participantsHTML}
          </div>
        `;

        activitiesList.appendChild(activityCard);

        // Add option to select dropdown
        const option = document.createElement("option");
        option.value = name;
        option.textContent = name;
        activitySelect.appendChild(option);
      });

      // Add event listeners to delete buttons
      document.querySelectorAll(".delete-btn").forEach((button) => {
        button.addEventListener("click", handleUnregister);
      });
    } catch (error) {
      activitiesList.innerHTML =
        "<p>Failed to load activities. Please try again later.</p>";
      console.error("Error fetching activities:", error);
    }
  }

  // Handle unregister functionality
  async function handleUnregister(event) {
    const button = event.target;
    const activity = button.getAttribute("data-activity");
    const token = getToken();

    try {
      const response = await fetch(`/activities/${encodeURIComponent(activity)}/unregister`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const result = await response.json();

      if (response.ok) {
        showMessage(result.message, "success");

        // Refresh activities list to show updated participants
        fetchActivities();
      } else if (response.status === 401) {
        handleUnauthorized();
      } else {
        showMessage(result.detail || "An error occurred", "error");
      }
    } catch (error) {
      showMessage("Failed to unregister. Please try again.", "error");
      console.error("Error unregistering:", error);
    }
  }

  async function refreshCurrentUser() {
    const token = getToken();
    if (!token) {
      currentUser = null;
      updateAuthUI();
      return;
    }

    try {
      const response = await fetch("/auth/me", {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const result = await response.json();
        currentUser = result.user;
      } else {
        currentUser = null;
        clearToken();
      }
    } catch (error) {
      currentUser = null;
      clearToken();
      console.error("Error fetching current user:", error);
    }

    updateAuthUI();
  }

  authForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const endpoint = authMode === "signup" ? "/auth/signup" : "/auth/login";
    const payload = {
      email: authEmailInput.value.trim(),
      password: authPasswordInput.value,
    };

    if (authMode === "signup") {
      payload.name = authNameInput.value.trim();
      payload.role = "student";
    }

    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      const result = await response.json();

      if (response.ok) {
        setToken(result.token);
        currentUser = result.user;
        updateAuthUI();
        authForm.reset();
        setAuthMode("login");
        showMessage(authMode === "signup" ? "Account created." : "Logged in successfully.", "success");
        fetchActivities();
      } else {
        showMessage(result.detail || "Authentication failed.", "error");
      }
    } catch (error) {
      showMessage("Authentication request failed.", "error");
      console.error("Authentication error:", error);
    }
  });

  logoutBtn.addEventListener("click", async () => {
    const token = getToken();

    try {
      if (token) {
        await fetch("/auth/logout", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
      }
    } catch (error) {
      console.error("Logout request failed:", error);
    }

    currentUser = null;
    clearToken();
    updateAuthUI();
    fetchActivities();
  });

  showLoginBtn.addEventListener("click", () => {
    setAuthMode("login");
  });

  showSignupBtn.addEventListener("click", () => {
    setAuthMode("signup");
  });

  // Handle form submission
  signupForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const activity = document.getElementById("activity").value;
    const token = getToken();

    try {
      const response = await fetch(`/activities/${encodeURIComponent(activity)}/signup`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const result = await response.json();

      if (response.ok) {
        showMessage(result.message, "success");
        signupForm.reset();

        // Refresh activities list to show updated participants
        fetchActivities();
      } else if (response.status === 401) {
        handleUnauthorized();
      } else {
        showMessage(result.detail || "An error occurred", "error");
      }
    } catch (error) {
      showMessage("Failed to sign up. Please try again.", "error");
      console.error("Error signing up:", error);
    }
  });

  setAuthMode("login");

  // Initialize app
  refreshCurrentUser().then(fetchActivities);
});
