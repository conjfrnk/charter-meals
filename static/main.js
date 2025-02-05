$(document).ready(function(){
  // Dismiss any element when its dismiss button is clicked (desktop only)
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
  // Auto-refresh counts every 5 minutes (300000 ms)
  setInterval(updateCounts, 300000);

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

  // Update eligibility dynamically based on current selections.
  function updateEligibility(){
    var totalSelected = $("input[name='meal_slot']:checked").length;
    var pubSelected = $("input[name='meal_slot'][data-pub='1']:checked").length;

    $("input[name='meal_slot']").each(function(){
      // Skip if originally disabled
      var originallyDisabled = $(this).data("original-disabled");
      if(originallyDisabled){
        return;
      }
      if(!$(this).is(":checked")){
        if(totalSelected >= 2) {
          $(this).prop("disabled", true);
        } else if($(this).data("pub") === 1 && pubSelected >= 1) {
          $(this).prop("disabled", true);
        } else {
          $(this).prop("disabled", false);
        }
      }
    });
  }

  $("input[type='checkbox'][name='meal_slot']").change(function(){
    var $this = $(this);
    enforceLimits($this);
    updateTimestamp();
    updateCounts();
    updateEligibility();
  });

  // Initial eligibility update on page load.
  updateEligibility();
  updateTimestamp();
});

