$(document).ready(function(){
  // Dismiss any element when its dismiss button is clicked (for desktop only)
  $(document).on('click', '.dismiss', function() {
    $(this).parent().fadeOut();
  });
  
  // Update the reservation counts shown next to each meal slot.
  function updateCounts(){
    $.getJSON("/meal_counts", function(data){
      $.each(data, function(slot_id, count){
        $("#count-" + slot_id).text(count + "/" + $("#count-" + slot_id).data("capacity") + " reservations");
      });
    });
  }
  updateCounts();
  setInterval(updateCounts, 10000);
  
  // Update the hidden client timestamp field with the current ISO timestamp.
  function updateTimestamp() {
    var ts = new Date().toISOString();
    $("#client_timestamp").val(ts);
    console.log("Timestamp updated: " + ts);
  }
  
  // Enforce selection limits on eligible checkboxes:
  // - Maximum 2 meals total.
  // - Maximum 1 pub night.
  function enforceLimits(changedCheckbox) {
    if(changedCheckbox.is(":checked")){
      var totalSelected = $("input[name='meal_slot']:checked").length;
      if(totalSelected > 2){
        alert("You cannot select more than 2 meals in total.");
        changedCheckbox.prop("checked", false);
        return;
      }
      if(changedCheckbox.data("pub") === 1){
        var pubCount = $("input[name='meal_slot'][data-pub='1']:checked").length;
        if(pubCount > 1){
          alert("You can only select 1 pub night.");
          changedCheckbox.prop("checked", false);
          return;
        }
      }
    }
  }
  
  $("input[type='checkbox'][name='meal_slot']").change(function(){
    var $this = $(this);
    enforceLimits($this);
    updateTimestamp();
  });
  
  $("#mealForm").submit(function(e){
    updateTimestamp();
    console.log("Form submitted with timestamp: " + $("#client_timestamp").val());
  });
  
  updateTimestamp();
});
