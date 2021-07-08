# Generated by default/object.tt
package Paws::CodeGuruReviewer::RecommendationSummary;
  use Moose;
  has Description => (is => 'ro', isa => 'Str');
  has EndLine => (is => 'ro', isa => 'Int');
  has FilePath => (is => 'ro', isa => 'Str');
  has RecommendationCategory => (is => 'ro', isa => 'Str');
  has RecommendationId => (is => 'ro', isa => 'Str');
  has StartLine => (is => 'ro', isa => 'Int');

1;

### main pod documentation begin ###

=head1 NAME

Paws::CodeGuruReviewer::RecommendationSummary

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::CodeGuruReviewer::RecommendationSummary object:

  $service_obj->Method(Att1 => { Description => $value, ..., StartLine => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::CodeGuruReviewer::RecommendationSummary object:

  $result = $service_obj->Method(...);
  $result->Att1->Description

=head1 DESCRIPTION

Information about recommendations.

=head1 ATTRIBUTES


=head2 Description => Str

A description of the recommendation generated by CodeGuru Reviewer for
the lines of code between the start line and the end line.


=head2 EndLine => Int

Last line where the recommendation is applicable in the source commit
or source branch. For a single line comment the start line and end line
values are the same.


=head2 FilePath => Str

Name of the file on which a recommendation is provided.


=head2 RecommendationCategory => Str

The type of a recommendation.


=head2 RecommendationId => Str

The recommendation ID that can be used to track the provided
recommendations. Later on it can be used to collect the feedback.


=head2 StartLine => Int

Start line from where the recommendation is applicable in the source
commit or source branch.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::CodeGuruReviewer>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

