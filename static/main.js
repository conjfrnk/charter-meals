$(document).ready(function(){
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

  function updateTimestamp() {
    var ts = new Date().toISOString();
    $("#client_timestamp").val(ts);
    console.log("Timestamp updated: " + ts);
  }

  function enforceLimits(changedCheckbox) {
    if (changedCheckbox.is(":checked")) {
      var totalSelected = $("input[name='meal_slot']:checked").length;
      if (totalSelected > 2) {
        alert("You cannot select more than 2 meals in total.");
        changedCheckbox.prop("checked", false);
        return;
      }
      if (changedCheckbox.data("pub") === 1) {
        var pubCount = $("input[name='meal_slot'][data-pub='1']:checked").length;
        if (pubCount > 1) {
          alert("You can only select 1 pub night.");
          changedCheckbox.prop("checked", false);
          return;
        }
      }
    }
    if ($("input[name='meal_slot']:checked").length >= 2) {
      $("input[name='meal_slot']").not(":checked").prop("disabled", true);
    } else {
      $("input[name='meal_slot']").each(function(){
        if (!$(this).hasClass("not-eligible")) {
          $(this).prop("disabled", false);
        }
      });
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
