$(document).ready(function(){
  function updateCounts(){
    $.getJSON("/meal_counts", function(data){
      $.each(data, function(slot_id, count){
        $("#count-" + slot_id).text(count);
      });
    });
  }
  updateCounts();
  // Update counts every 10 seconds
  setInterval(updateCounts, 10000);
});
