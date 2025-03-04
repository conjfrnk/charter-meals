document.addEventListener('DOMContentLoaded', () => {
  // Dismiss elements when a dismiss button is clicked
  document.addEventListener('click', (event) => {
    if (event.target.classList.contains('dismiss')) {
      const parent = event.target.parentElement;
      // Fade out effect with CSS transitions (add to your CSS: .fade-out { opacity: 0; transition: opacity 0.5s; })
      parent.classList.add('fade-out');
      setTimeout(() => {
        parent.style.display = 'none';
      }, 500);
    }
  });

  // Update the reservation counts every 5 seconds
  function updateCounts() {
    fetch('/meal_counts')
      .then(response => response.json())
      .then(data => {
        Object.entries(data).forEach(([slotId, count]) => {
          const element = document.getElementById(`count-${slotId}`);
          if (element) {
            const capacity = element.dataset.capacity;
            element.textContent = `${count}/${capacity} reservations`;
          }
        });
      })
      .catch(error => console.error('Error fetching meal counts:', error));
  }
  
  // Run initial count update and set interval
  if (document.getElementById('mealForm')) {
    updateCounts();
    setInterval(updateCounts, 5000);
  }

  // Main Admin Tabs - remember last active tab
  const tabLinks = document.querySelectorAll('.tablink');
  if (tabLinks.length > 0) {
    const tabContents = document.querySelectorAll('.tabcontent');
    let activeTab = localStorage.getItem('activeAdminTab') || 'reservations';
    
    function showTab(tabName) {
      tabLinks.forEach(link => {
        link.classList.toggle('active', link.dataset.tab === tabName);
      });
      
      tabContents.forEach(content => {
        content.style.display = content.id === tabName ? 'block' : 'none';
      });
    }
    
    tabLinks.forEach(link => {
      link.addEventListener('click', () => {
        const tabName = link.dataset.tab;
        localStorage.setItem('activeAdminTab', tabName);
        showTab(tabName);
      });
    });
    
    showTab(activeTab);
  }

  // Reservations Subtabs Logic - remember last active subtab
  const subtabBtns = document.querySelectorAll('.subtab-btn');
  if (subtabBtns.length > 0) {
    const subtabContents = document.querySelectorAll('.subtab-content');
    let activeSubtab = localStorage.getItem('activeReservationSubtab') || 'download';
    
    function showSubtab(subtabName) {
      subtabBtns.forEach(btn => {
        btn.classList.toggle('active', btn.dataset.subtab === subtabName);
      });
      
      subtabContents.forEach(content => {
        content.classList.toggle('active', content.id === subtabName);
      });
    }
    
    subtabBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const subtabName = btn.dataset.subtab;
        localStorage.setItem('activeReservationSubtab', subtabName);
        showSubtab(subtabName);
      });
    });
    
    showSubtab(activeSubtab);
  }

  // Toggle password visibility
  const togglePasswordBtns = document.querySelectorAll('.toggle-password');
  togglePasswordBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.target;
      const input = document.getElementById(targetId);
      
      if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = 'Hide Password';
      } else {
        input.type = 'password';
        btn.textContent = 'Show Password';
      }
    });
  });

  // Meal selection logic
  const mealSlotCheckboxes = document.querySelectorAll('input[name="meal_slot"]');
  if (mealSlotCheckboxes.length > 0) {
    const mealForm = document.getElementById('mealForm');
    const maxMeals = parseInt(mealForm.dataset.maxMeals) || 2;
    
    function updateCheckboxStates() {
      // Count selected slots
      const selectedCount = document.querySelectorAll('input[name="meal_slot"]:checked').length;
      
      if (selectedCount >= maxMeals) {
        // Disable unchecked meal slots
        mealSlotCheckboxes.forEach(checkbox => {
          if (!checkbox.checked && !checkbox.disabled) {
            checkbox.disabled = true;
            checkbox.classList.add('temp-disabled');
          }
        });
      } else {
        // Re-enable temporarily disabled checkboxes
        document.querySelectorAll('input[name="meal_slot"].temp-disabled').forEach(checkbox => {
          if (!checkbox.classList.contains('perma-disabled')) {
            checkbox.disabled = false;
            checkbox.classList.remove('temp-disabled');
          }
        });
      }
      
      updatePubNightCheckboxes();
    }
    
    function updatePubNightCheckboxes() {
      const selectedCount = document.querySelectorAll('input[name="meal_slot"]:checked').length;
      if (selectedCount >= maxMeals) return;
      
      // Check if any pub night is selected
      let pubSelected = false;
      mealSlotCheckboxes.forEach(checkbox => {
        if (checkbox.dataset.pub === '1' && checkbox.checked) {
          pubSelected = true;
        }
      });
      
      if (pubSelected) {
        // Disable unselected pub nights
        mealSlotCheckboxes.forEach(checkbox => {
          if (checkbox.dataset.pub === '1' && !checkbox.checked && !checkbox.disabled) {
            checkbox.disabled = true;
            checkbox.classList.add('temp-disabled');
          }
        });
      } else {
        // Re-enable temporarily disabled pub nights
        mealSlotCheckboxes.forEach(checkbox => {
          if (checkbox.dataset.pub === '1' && checkbox.classList.contains('temp-disabled') && 
              !checkbox.classList.contains('perma-disabled')) {
            checkbox.disabled = false;
            checkbox.classList.remove('temp-disabled');
          }
        });
      }
    }
    
    // Add event listeners to all checkboxes
    mealSlotCheckboxes.forEach(checkbox => {
      checkbox.addEventListener('change', updateCheckboxStates);
    });
    
    // Initial update
    updateCheckboxStates();
  }
});

