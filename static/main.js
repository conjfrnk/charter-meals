$(document).ready(function(){
  // Updates the reservation counts shown next to each meal slot by querying the server.
  function updateCounts(){
    $.getJSON("/meal_counts", function(data){
      $.each(data, function(slot_id, count){
        var countSpan = $("#count-" + slot_id);
        var capacity = countSpan.data("capacity");
        countSpan.text(count + "/" + capacity + " reservations");
        var checkbox = $("input[name='meal_slot'][value='" + slot_id + "']");
        // If the slot is at capacity and not selected, disable it.
        if(count >= capacity && !checkbox.is(":checked")){
          checkbox.prop("disabled", true);
          checkbox.parent().addClass("full");
        } else {
          // Otherwise, if not already selected and not marked ineligible, enable it.
          if(!checkbox.is(":checked") && !checkbox.hasClass("not-eligible")){
            checkbox.prop("disabled", false);
          }
          checkbox.parent().removeClass("full");
        }
      });
    });
  }
  updateCounts();
  setInterval(updateCounts, 10000);

  // Updates the hidden client timestamp field with the current ISO timestamp.
  function updateTimestamp() {
    var ts = new Date().toISOString();
    $("#client_timestamp").val(ts);
    console.log("Timestamp updated: " + ts);
  }

  // Enforces the selection limits:
  // - Maximum 2 meals overall.
  // - Maximum 1 pub night.
  function enforceLimits(changedCheckbox) {
    var totalSelected = $("input[name='meal_slot']:checked").length;
    if(changedCheckbox.is(":checked")){
      if(totalSelected > 2){
        alert("You cannot select more than 2 meals in total.");
        changedCheckbox.prop("checked", false);
        return;
      }
      // If the changed checkbox represents a pub night, enforce the pub limit.
      if(changedCheckbox.data("pub") === 1){
        var pubCount = $("input[name='meal_slot'][data-pub='1']:checked").length;
        if(pubCount > 1){
          alert("You can only select 1 pub night.");
          changedCheckbox.prop("checked", false);
          return;
        }
      }
    }
    // Disable all unchecked checkboxes if already 2 meals are selected.
    if($("input[name='meal_slot']:checked").length >= 2){
      $("input[name='meal_slot']").not(":checked").prop("disabled", true);
    } else {
      // Otherwise, re-enable any checkbox that is not marked as not-eligible.
      $("input[name='meal_slot']").each(function(){
        if(!$(this).hasClass("not-eligible")){
          $(this).prop("disabled", false);
        }
      });
    }
  }

  // Attach the change event handler to meal slot checkboxes.
  $("input[type='checkbox'][name='meal_slot']").change(function(){
    var $this = $(this);
    enforceLimits($this);
    updateTimestamp();
  });

  // When the form is submitted, update the timestamp and ensure it is present.
  $("#mealForm").submit(function(e){
    updateTimestamp();
    if($("#client_timestamp").val() === ""){
      alert("Client timestamp missing. Please try again.");
      e.preventDefault();
    } else {
      console.log("Form submitted with timestamp: " + $("#client_timestamp").val());
    }
  });

  // Initial timestamp update.
  updateTimestamp();
});
