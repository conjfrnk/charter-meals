$(document).ready(function(){
  // Function to update the reservation counts next to each meal slot.
  function updateCounts(){
    $.getJSON("/meal_counts", function(data){
      $.each(data, function(slot_id, count){
        $("#count-" + slot_id).text(count);
      });
    });
  }
  updateCounts();
  // Update counts every 10 seconds.
  setInterval(updateCounts, 10000);
  
  // If the meal signup form exists, attach event handlers.
  if ($("#mealForm").length) {
    // On form submit, update the client timestamp.
    $("#mealForm").submit(function(e){
      $("#client_timestamp").val(new Date().toISOString());
    });
    
    // Enforce maximum selection limits:
    // - Maximum of 2 non-pub meals.
    // - Maximum of 1 pub night.
    $("input[type='checkbox'][name='meal_slot']").change(function(e){
      var pubCount = $("input[type='checkbox'][name='meal_slot'][data-pub='1']:checked").length;
      var nonPubCount = $("input[type='checkbox'][name='meal_slot'][data-pub='0']:checked").length;
      if ($(this).is(':checked')) {
        if ($(this).data('pub') == 1 && pubCount > 1) {
          alert("You can only select 1 pub night. Please deselect the other pub night.");
          $(this).prop('checked', false);
        }
        if ($(this).data('pub') == 0 && nonPubCount > 2) {
          alert("You can only select 2 meals. Please deselect one to select a new one.");
          $(this).prop('checked', false);
        }
      }
    });
  }
});
