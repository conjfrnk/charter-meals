$(document).ready(function(){
  // Dismiss elements when a dismiss button is clicked.
  $(document).on('click', '.dismiss', function() {
    $(this).parent().fadeOut();
  });

  // Update the reservation counts every 5 seconds.
  function updateCounts(){
    $.getJSON("/meal_counts", function(data){
      $.each(data, function(slot_id, count){
        $("#count-" + slot_id).text(count + "/" + $("#count-" + slot_id).data("capacity") + " reservations");
      });
    });
  }
  updateCounts();
  setInterval(updateCounts, 5000);

  // Before reservation form submission, update the hidden timestamp to the current time.
  $("#mealForm").on("submit", function(){
    var ts = new Date().toISOString();
    $("#client_timestamp").val(ts);
  });

  // Main Admin Tabs – remember last active tab.
  if ($(".tablink").length > 0) {
    const tabLinks = $(".tablink");
    const tabContents = $(".tabcontent");
    let activeTab = localStorage.getItem("activeAdminTab") || "reservations";
    function showTab(tabName) {
      tabLinks.each(function(){
        $(this).toggleClass("active", $(this).data("tab") === tabName);
      });
      tabContents.each(function(){
        $(this).toggle($(this).attr("id") === tabName);
      });
    }
    tabLinks.click(function(){
      let tabName = $(this).data("tab");
      localStorage.setItem("activeAdminTab", tabName);
      showTab(tabName);
    });
    showTab(activeTab);
  }

  // Reservations Subtabs Logic – remember last active subtab.
  if ($(".subtab-btn").length > 0) {
    const subtabBtns = $(".subtab-btn");
    const subtabContents = $(".subtab-content");
    let activeSubtab = localStorage.getItem("activeReservationSubtab") || "download";
    function showSubtab(subtabName) {
      subtabBtns.each(function(){
        $(this).toggleClass("active", $(this).data("subtab") === subtabName);
      });
      subtabContents.each(function(){
        $(this).toggleClass("active", $(this).attr("id") === subtabName);
      });
    }
    subtabBtns.click(function(){
      let subtabName = $(this).data("subtab");
      localStorage.setItem("activeReservationSubtab", subtabName);
      showSubtab(subtabName);
    });
    showSubtab(activeSubtab);
  }

  // Toggle password visibility.
  $(".toggle-password").click(function(){
    let targetId = $(this).data("target");
    let input = $("#" + targetId);
    if (input.attr("type") === "password") {
      input.attr("type", "text");
      $(this).text("Hide Password");
    } else {
      input.attr("type", "password");
      $(this).text("Show Password");
    }
  });

  // Limit meal selection based on the allowed number.
  // Read the allowed maximum from the form's data attribute (default is 2).
  const maxMeals = parseInt($("#mealForm").data("max-meals")) || 2;
  $('input[name="meal_slot"]').on('change', function(){
    // Count how many meal slots are checked overall.
    let selectedCount = $('input[name="meal_slot"]:checked').length;

    if(selectedCount >= maxMeals){
      // Disable (gray out) any unchecked meal slot
      $('input[name="meal_slot"]').each(function(){
        if(!$(this).is(':checked') && !$(this).prop('disabled')){
          $(this).prop('disabled', true).addClass('temp-disabled');
        }
      });
    } else {
      // Re-enable any checkboxes that were temporarily disabled (if not permanently disabled)
      $('input[name="meal_slot"].temp-disabled').each(function(){
        if(!$(this).hasClass('perma-disabled')){
          $(this).prop('disabled', false).removeClass('temp-disabled');
        }
      });
    }
    updatePubNightCheckboxes();
  });

  function updatePubNightCheckboxes() {
    // Get the overall selected count
    let selectedCount = $('input[name="meal_slot"]:checked').length;
    // If we've already hit the max, do nothing
    const maxMeals = parseInt($("#mealForm").data("max-meals")) || 2;
    if (selectedCount >= maxMeals) {
      return;
    }

    // Otherwise, check if any pub night is selected
    let pubSelected = false;
    $('input[name="meal_slot"]').each(function(){
      if ($(this).data("pub") == 1 && $(this).is(":checked")) {
        pubSelected = true;
      }
    });
    if(pubSelected) {
      $('input[name="meal_slot"]').each(function(){
        if ($(this).data("pub") == 1 && !$(this).is(":checked") && !$(this).prop("disabled")){
          $(this).prop("disabled", true).addClass("temp-disabled");
        }
      });
    } else {
      $('input[name="meal_slot"]').each(function(){
        if ($(this).data("pub") == 1 && $(this).hasClass("temp-disabled") && !$(this).hasClass("perma-disabled")){
          $(this).prop("disabled", false).removeClass("temp-disabled");
        }
      });
    }
  }

  // Call updatePubNightCheckboxes initially
  updatePubNightCheckboxes();

  // NEW: Trigger a change event on all checkboxes to ensure that if 2 meals are already selected,
  // all other unchecked checkboxes (pub or non-pub) are disabled.
  $('input[name="meal_slot"]').trigger('change');
});
