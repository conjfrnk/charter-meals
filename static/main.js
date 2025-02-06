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
});
