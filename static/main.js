$(document).ready(function(){
  // Function to update the reservation counts next to each meal slot.
  function updateCounts(){
    $.getJSON("/meal_counts", function(data){
      $.each(data, function(slot_id, count){
        var countSpan = $("#count-" + slot_id);
        var capacity = countSpan.data("capacity");
        countSpan.text(count + "/" + capacity + " reservations");
        var checkbox = $("input[name='meal_slot'][value='" + slot_id + "']");
        if(count >= capacity && !checkbox.is(":checked")){
          checkbox.prop("disabled", true);
          checkbox.parent().addClass("full");
        } else {
          if(!checkbox.is(":checked")){
            checkbox.prop("disabled", false);
          }
          checkbox.parent().removeClass("full");
        }
      });
    });
  }
  updateCounts();
  // Update counts every 10 seconds.
  setInterval(updateCounts, 10000);
  
  // Function to update the client timestamp.
  function updateTimestamp() {
    var ts = new Date().toISOString();
    $("#client_timestamp").val(ts);
    console.log("Timestamp updated: " + ts);
  }

  // Enforce selection limits on change (this code remains from previous functionality).
  function enforceLimits(changedCheckbox) {
    var pubCount = $("input[name='meal_slot'][data-pub='1']:checked").length;
    var nonPubCount = $("input[name='meal_slot'][data-pub='0']:checked").length;
    if (changedCheckbox.data('pub') === 1 && pubCount > 1) {
      alert("You can only select 1 pub night. Please deselect the other pub night.");
      changedCheckbox.prop('checked', false);
      return;
    }
    if (changedCheckbox.data('pub') === 0 && nonPubCount > 2) {
      alert("You can only select 2 meals. Please deselect one to select a new one.");
      changedCheckbox.prop('checked', false);
      return;
    }
    // Optionally, disable unchecked checkboxes if the limit is reached.
    $("input[name='meal_slot'][data-pub='1']").each(function(){
      if (!$(this).is(':checked')) {
        if ($("input[name='meal_slot'][data-pub='1']:checked").length >= 1) {
          $(this).prop('disabled', true);
        } else {
          $(this).prop('disabled', false);
        }
      }
    });
    $("input[name='meal_slot'][data-pub='0']").each(function(){
      if (!$(this).is(':checked')) {
        if ($("input[name='meal_slot'][data-pub='0']:checked").length >= 2) {
          $(this).prop('disabled', true);
        } else {
          $(this).prop('disabled', false);
        }
      }
    });
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
